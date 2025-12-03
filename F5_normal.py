# F5_normal.py (Final Production Version)
import os
import logging
import re
import sys
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from datetime import datetime

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("f5_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "F5"

# --- Helper Functions ---
def safe_numeric(value):
    try:
        if value is None or str(value).strip() == "" or str(value).lower() in ["none", "not applicable"]:
            return None
        return float(value)
    except (ValueError, TypeError):
        return None

def safe_date(value):
    try:
        return datetime.strptime(value, "%A, %B %d, %Y").date()
    except (ValueError, TypeError):
        return None

def extract_severity_and_score(vuln, products):
    severity = vuln.get("severity")
    score = vuln.get("cvss_score")

    if not severity or severity.strip() == "":
        for p in products:
            sev = p.get("severity") or p.get("severity_cvss_score")
            if sev and "/" in sev:
                parts = sev.split("/")
                severity = parts[0].strip()
                if len(parts) > 1:
                    score_match = re.search(r'([\d\.]+)', parts[1])
                    if score_match:
                        score = score_match.group(1)
                break
            elif sev:
                severity = sev
    if not score or str(score).strip() == "":
        for p in products:
            for k in ["cvssv3_score", "cvssv3_score_1", "cvssv3_score_2"]:
                if p.get(k) and p[k] not in ("None", "Not applicable"):
                    score = p[k]
                    break
    return severity, score

# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                # Ensure Vendor Exists
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]
                
                # Fetch Staging Data
                cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE vendor_name=%s AND processed=false", (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info(f"No new {VENDOR_NAME} records to process.")
                    return

                logger.info(f"Normalizing {len(rows)} new records...")
                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in rows:
                    kb_id = raw_data.get("kb_id")
                    if not kb_id: continue

                    vuln = raw_data.get("vulnerability_details", {})
                    products = raw_data.get("product_impact_information", {}).get("affected_products", [])
                    cve_ids = vuln.get("cve_ids", [])
                    
                    if not cve_ids: cve_ids = [f"NO-CVE-{kb_id}"]

                    severity, score = extract_severity_and_score(vuln, products)
                    
                    # 1. Advisories
                    advisories[kb_id] = (
                        kb_id, vendor_id, raw_data.get("title"), severity,
                        safe_date(raw_data.get("publication_date")),
                        safe_date(raw_data.get("modification_date")),
                        raw_data.get("url")
                    )

                    for cve_id in cve_ids:
                        cve_key = (vendor_id, cve_id)
                        
                        # 2. CVEs
                        cves[cve_key] = (
                            vendor_id, cve_id,
                            (vuln.get("cwe_ids") or [None])[0],
                            vuln.get("cve_descriptions", {}).get(cve_id) or raw_data.get("technical_content", {}).get("summary"),
                            None, safe_numeric(score), 
                            None, None, None, None # Vector, Dates, Ref URL are NULL
                        )
                        
                        # 3. Product Map
                        cve_product_maps[cve_key] = (vendor_id, cve_id, None, None)
                        
                        # 4. Map
                        advisory_cves_map.add((kb_id, vendor_id, cve_id))

                logger.info("Performing bulk database inserts...")
                
                # --- SQL LOGIC: Living Database + Sequence Sync ---

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) 
                        VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET 
                        title=EXCLUDED.title, 
                        severity=EXCLUDED.severity, 
                        latest_update_date=EXCLUDED.latest_update_date,
                        advisory_url=EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        cwe_id=EXCLUDED.cwe_id, 
                        cvss_score=EXCLUDED.cvss_score,
                        description=COALESCE(EXCLUDED.description, cves.description), 
                        severity=COALESCE(EXCLUDED.severity, cves.severity);
                    """, list(cves.values()))

                if cve_product_maps:
                    # --- CRITICAL FIX: Sync the Sequence ---
                    cur.execute("""
                        SELECT setval('qs_id_seq', COALESCE((
                            SELECT MAX(SUBSTRING(qs_id FROM 4)::INTEGER) 
                            FROM cve_product_map
                        ), 0) + 1);
                    """)

                    # --- CRITICAL FIX: Update data without breaking qs_id ---
                    execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        recommendations=EXCLUDED.recommendations,
                        affected_products_cpe=EXCLUDED.affected_products_cpe;
                    """, list(cve_product_maps.values()))
                
                if advisory_cves_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) 
                        VALUES %s ON CONFLICT DO NOTHING;
                    """, list(advisory_cves_map))

                # Mark processed + Timestamp
                processed_ids = tuple(row[0] for row in rows)
                if processed_ids:
                    cur.execute("UPDATE vendor_staging_table SET processed = TRUE, processed_at = NOW() WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        if 'conn' in locals() and conn: conn.rollback()

if __name__ == "__main__":
    main()




'''
# F5_normal.py (Production Version)
import os
import logging
import re
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from datetime import datetime

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("f5_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "F5"

# --- Helper Functions (Your Original Core Logic) ---
def safe_numeric(value):
    try:
        if value is None or str(value).strip() == "" or str(value).lower() in ["none", "not applicable"]:
            return None
        return float(value)
    except (ValueError, TypeError):
        return None

def safe_date(value):
    try:
        return datetime.strptime(value, "%A, %B %d, %Y").date()
    except (ValueError, TypeError):
        return None

def extract_severity_and_score(vuln, products):
    severity = vuln.get("severity")
    score = vuln.get("cvss_score")

    if not severity or severity.strip() == "":
        for p in products:
            sev = p.get("severity") or p.get("severity_cvss_score")
            if sev and "/" in sev:
                parts = sev.split("/")
                severity = parts[0].strip()
                if len(parts) > 1:
                    score_match = re.search(r'([\d\.]+)', parts[1])
                    if score_match:
                        score = score_match.group(1)
                break
            elif sev:
                severity = sev
    if not score or str(score).strip() == "":
        for p in products:
            for k in ["cvssv3_score", "cvssv3_score_1", "cvssv3_score_2"]:
                if p.get(k) and p[k] not in ("None", "Not applicable"):
                    score = p[k]
                    break
    return severity, score

# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]
                
                cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE vendor_name=%s AND processed=false", (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info(f"No new {VENDOR_NAME} records to process.")
                    return

                logger.info(f"Normalizing {len(rows)} new records...")
                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in rows:
                    kb_id = raw_data.get("kb_id")
                    if not kb_id: continue

                    vuln = raw_data.get("vulnerability_details", {})
                    products = raw_data.get("product_impact_information", {}).get("affected_products", [])
                    cve_ids = vuln.get("cve_ids", [])
                    
                    if not cve_ids: cve_ids = [f"NO-CVE-{kb_id}"]

                    severity, score = extract_severity_and_score(vuln, products)
                    
                    advisories[kb_id] = (
                        kb_id, vendor_id, raw_data.get("title"), severity,
                        safe_date(raw_data.get("publication_date")),
                        safe_date(raw_data.get("modification_date")),
                        raw_data.get("url")
                    )

                    for cve_id in cve_ids:
                        cve_key = (vendor_id, cve_id)
                        cves[cve_key] = (
                            vendor_id, cve_id,
                            (vuln.get("cwe_ids") or [None])[0],
                            vuln.get("cve_descriptions", {}).get(cve_id) or raw_data.get("technical_content", {}).get("summary"),
                            None, safe_numeric(score), 
                            None, None, None, None # Vector, Dates, Ref URL are NULL
                        )
                        cve_product_maps[cve_key] = (vendor_id, cve_id, None, None) # Recommendations is NULL
                        advisory_cves_map.add((kb_id, vendor_id, cve_id))

                logger.info("Performing bulk database inserts...")
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, latest_update_date=EXCLUDED.latest_update_date;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET cwe_id=EXCLUDED.cwe_id, description=EXCLUDED.description, severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score;
                    """, list(cves.values()))

                if cve_product_maps:
                    execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO NOTHING;
                    """, list(cve_product_maps.values()))
                
                if advisory_cves_map:
                    execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cves_map))

                processed_ids = tuple(row[0] for row in rows)
                if processed_ids:
                    cur.execute("UPDATE vendor_staging_table SET processed = TRUE, processed_at = NOW() WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        if 'conn' in locals() and conn: conn.rollback()

if __name__ == "__main__":
    main()
'''    
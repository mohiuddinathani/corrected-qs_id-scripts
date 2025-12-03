# ubiquiti_normal.py (Production Version)
import os
import logging
import psycopg2
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv
from tqdm import tqdm
from datetime import datetime
import sys

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("ubiquiti_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "Ubiquiti"

# --- Helper Functions ---
def parse_date(date_string):
    """Safely parses ISO 8601 date strings into date objects."""
    if not date_string: return None
    try:
        return datetime.fromisoformat(date_string.replace("Z", "+00:00")).date()
    except (ValueError, TypeError):
        return None

def parse_cvss(cvss_string):
    """Extracts score and severity from a combined string like '9.8 Critical'."""
    if not isinstance(cvss_string, str): return None, None
    parts = cvss_string.strip().split()
    score, severity = None, None
    try:
        score = float(parts[0])
        if len(parts) > 1: severity = parts[1].capitalize()
    except (ValueError, IndexError):
        return None, None
    return score, severity

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

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()
                severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    advisory_id = raw_data.get("id")
                    if not advisory_id: continue

                    summaries = raw_data.get("summaries", [])
                    initial_date = parse_date(raw_data.get("createdAt"))
                    latest_date = parse_date(raw_data.get("lastActivityAt"))
                    
                    # Determine the highest severity from all CVEs in the advisory
                    highest_severity_str = None
                    max_level = 0
                    for s in summaries:
                        _, severity = parse_cvss(s.get("cvss_base_score"))
                        if severity and severity_map.get(severity, 0) > max_level:
                            max_level = severity_map.get(severity, 0)
                            highest_severity_str = severity
                    
                    # 1. Advisory Record
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("title"),
                        highest_severity_str, initial_date, latest_date, raw_data.get("url")
                    )

                    for s in summaries:
                        cve_id = s.get("cve")
                        if not cve_id: continue

                        cvss_score, severity = parse_cvss(s.get("cvss_base_score"))
                        cve_key = (vendor_id, cve_id)
                        
                        # 2. CVE Record
                        cves[cve_key] = (
                            vendor_id, cve_id, s.get("cwe"), s.get("description"),
                            severity, cvss_score, s.get("cvss_vector"),
                            None,  None, s.get("cve_link")
                        )
                        
                        # 3. Product Map
                        cve_product_maps[cve_key] = (
                            vendor_id, cve_id, None, s.get("mitigation")
                        )
                        
                        # 4. Map
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

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
                        description=COALESCE(EXCLUDED.description, cves.description), 
                        severity=COALESCE(EXCLUDED.severity, cves.severity), 
                        cvss_score=COALESCE(EXCLUDED.cvss_score, cves.cvss_score), 
                        cvss_vector=COALESCE(EXCLUDED.cvss_vector, cves.cvss_vector), 
                        latest_update_date=EXCLUDED.latest_update_date,
                        reference_url=EXCLUDED.reference_url;
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
                        recommendations=EXCLUDED.recommendations;
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

if __name__ == "__main__":
    main()


'''
# ubiquiti_normal.py (Production Version)
import os
import logging
import psycopg2
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv
from tqdm import tqdm
from datetime import datetime

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("ubiquiti_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "Ubiquiti"

# --- Helper Functions ---
def parse_date(date_string):
    """Safely parses ISO 8601 date strings into date objects."""
    if not date_string: return None
    try:
        return datetime.fromisoformat(date_string.replace("Z", "+00:00")).date()
    except (ValueError, TypeError):
        return None

def parse_cvss(cvss_string):
    """Extracts score and severity from a combined string like '9.8 Critical'."""
    if not isinstance(cvss_string, str): return None, None
    parts = cvss_string.strip().split()
    score, severity = None, None
    try:
        score = float(parts[0])
        if len(parts) > 1: severity = parts[1].capitalize()
    except (ValueError, IndexError):
        return None, None
    return score, severity

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

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()
                severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    advisory_id = raw_data.get("id")
                    if not advisory_id: continue

                    summaries = raw_data.get("summaries", [])
                    initial_date = parse_date(raw_data.get("createdAt"))
                    latest_date = parse_date(raw_data.get("lastActivityAt"))
                    
                    # Determine the highest severity from all CVEs in the advisory
                    highest_severity_str = None
                    max_level = 0
                    for s in summaries:
                        _, severity = parse_cvss(s.get("cvss_base_score"))
                        if severity and severity_map.get(severity, 0) > max_level:
                            max_level = severity_map.get(severity, 0)
                            highest_severity_str = severity
                    
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("title"),
                         None, initial_date, latest_date, raw_data.get("url")
                    )

                    for s in summaries:
                        cve_id = s.get("cve")
                        if not cve_id: continue

                        cvss_score, severity = parse_cvss(s.get("cvss_base_score"))
                        
                        cves[(vendor_id, cve_id)] = (
                            vendor_id, cve_id, s.get("cwe"), s.get("description"),
                            severity, cvss_score, s.get("cvss_vector"),
                             None,  None, s.get("cve_link")
                        )
                        cve_product_maps[(vendor_id, cve_id)] = (
                            vendor_id, cve_id, None, s.get("mitigation")
                        )
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk database inserts...")
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, latest_update_date=EXCLUDED.latest_update_date;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET cwe_id=EXCLUDED.cwe_id, description=EXCLUDED.description, severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score, cvss_vector=EXCLUDED.cvss_vector, latest_update_date=EXCLUDED.latest_update_date;
                    """, list(cves.values()))

                if cve_product_maps:
                    execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET affected_products_cpe=EXCLUDED.affected_products_cpe, recommendations=EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))

                if advisory_cves_map:
                    execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cves_map))

                processed_ids = tuple(row[0] for row in rows)
                if processed_ids:
                    cur.execute("UPDATE vendor_staging_table SET processed = TRUE, processed_at = NOW() WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} {VENDOR_NAME} records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        if 'conn' in locals() and conn: conn.rollback()

if __name__ == "__main__":
    main()
'''
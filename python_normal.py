# python_normal.py (Final Production Version)
import os
import re
import logging
import sys
import psycopg2
from psycopg2.extras import execute_values, Json
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("python_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Python"

# --- Helper Functions ---
def clean_text(text):
    if not text: return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(date_str):
    if not date_str: return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00")).date()
    except (ValueError, TypeError):
        return None

def extract_cvss_details(data):
    if cvss := data.get("database_specific", {}).get("cvss"):
        return cvss.get("score"), cvss.get("vectorString")
    for aff in data.get("affected", []):
        if cvss := aff.get("database_specific", {}).get("cvss"):
            if score := cvss.get("score"):
                return score, cvss.get("vectorString")
    return None, None

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

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    advisory_id = raw_data.get("id")
                    if not advisory_id: continue

                    cve_aliases = [alias for alias in raw_data.get("aliases", []) if alias.startswith("CVE-")]
                    if not cve_aliases: cve_aliases.append(advisory_id)

                    advisory_url = next((ref.get("url") for ref in raw_data.get("references", []) if ref.get("type") == "ADVISORY"), f"https://osv.dev/vulnerability/{advisory_id}")

                    # 1. Advisory
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("summary"),
                        raw_data.get("database_specific", {}).get("severity"),
                        parse_date(raw_data.get("published")),
                        parse_date(raw_data.get("modified")),
                        advisory_url
                    )
                    
                    cvss_score, cvss_vector = extract_cvss_details(raw_data)
                    recommendations = []
                    
                    for cve_id in cve_aliases:
                        cve_key = (vendor_id, cve_id)
                        
                        # 2. CVE Record
                        cves[cve_key] = (
                            vendor_id, cve_id, 
                            None, # cwe_id
                            clean_text(raw_data.get("details")),
                            raw_data.get("database_specific", {}).get("severity"),
                            cvss_score, cvss_vector,
                            None, None, # dates
                            advisory_url
                        )

                        for affected in raw_data.get("affected", []):
                            product = (affected.get("package", {}) or {}).get("name", "python")
                            recommendations.append(f"Package: {product}. See advisory for patching details.")
                            
                        # 3. Product Map
                        cve_product_maps[cve_key] = (
                            vendor_id, cve_id, 
                            None, # affected_products_cpe
                            "\n".join(set(recommendations)) or None
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
                        description=COALESCE(EXCLUDED.description, cves.description), 
                        severity=COALESCE(EXCLUDED.severity, cves.severity), 
                        cvss_score=COALESCE(EXCLUDED.cvss_score, cves.cvss_score), 
                        cvss_vector=COALESCE(EXCLUDED.cvss_vector, cves.cvss_vector), 
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

if __name__ == "__main__":
    main()


'''
# python_normal.py (Production Version)
import os
import re
import logging
import psycopg2
from psycopg2.extras import execute_values, Json
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("python_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Python"

# --- Helper Functions (from your team's script) ---
def clean_text(text):
    if not text: return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(date_str):
    if not date_str: return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00")).date()
    except (ValueError, TypeError):
        return None

def extract_cvss_details(data):
    if cvss := data.get("database_specific", {}).get("cvss"):
        return cvss.get("score"), cvss.get("vectorString")
    for aff in data.get("affected", []):
        if cvss := aff.get("database_specific", {}).get("cvss"):
            if score := cvss.get("score"):
                return score, cvss.get("vectorString")
    return None, None

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

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    advisory_id = raw_data.get("id")
                    if not advisory_id: continue

                    cve_aliases = [alias for alias in raw_data.get("aliases", []) if alias.startswith("CVE-")]
                    if not cve_aliases: cve_aliases.append(advisory_id)

                    advisory_url = next((ref.get("url") for ref in raw_data.get("references", []) if ref.get("type") == "ADVISORY"), f"https://osv.dev/vulnerability/{advisory_id}")

                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("summary"),
                        raw_data.get("database_specific", {}).get("severity"),
                        parse_date(raw_data.get("published")),
                        parse_date(raw_data.get("modified")),
                        advisory_url
                    )
                    
                    cvss_score, cvss_vector = extract_cvss_details(raw_data)
                    recommendations = []
                    
                    for cve_id in cve_aliases:
                        # CVE Record - specified columns are NULL
                        cves[(vendor_id, cve_id)] = (
                            vendor_id, cve_id, None, # cwe_id
                            clean_text(raw_data.get("details")),
                            raw_data.get("database_specific", {}).get("severity"),
                            cvss_score, cvss_vector,
                            None, None, # initial/latest release dates
                            advisory_url
                        )

                        for affected in raw_data.get("affected", []):
                            product = (affected.get("package", {}) or {}).get("name", "python")
                            recommendations.append(f"Package: {product}. See advisory for patching details.")
                            
                            cve_product_maps[(vendor_id, cve_id)] = (vendor_id, cve_id, None, "\n".join(set(recommendations)) or None)

                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, latest_update_date=EXCLUDED.latest_update_date;
                    """, list(advisories.values()))
                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET description=EXCLUDED.description, severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score, cvss_vector=EXCLUDED.cvss_vector, reference_url=EXCLUDED.reference_url;
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
                    cur.execute("UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} {VENDOR_NAME} records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()
'''
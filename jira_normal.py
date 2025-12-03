# Jira_normal.py (Final Production Version)
import os
import re
import logging
import sys
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("jira_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Atlassian"

# --- Helper Functions ---
def clean_text(text):
    if not text: return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(ts_str):
    if not ts_str: return None
    try:
        return datetime.fromisoformat(ts_str.replace("+0000", "+00:00")).date()
    except (ValueError, TypeError):
        return None

def get_severity_from_score(score_val):
    if score_val is None: return "Unknown"
    try:
        score = float(score_val)
        if score >= 9.0: return "Critical"
        if score >= 7.0: return "High"
        if score >= 4.0: return "Medium"
        if score > 0: return "Low"
        return "None"
    except (ValueError, TypeError):
        return "Unknown"

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
                    # Use a combination of fields to create a unique advisory ID
                    year = parse_date(raw_data.get('cve_publish_date')).year if parse_date(raw_data.get('cve_publish_date')) else datetime.now().year
                    cve_id = raw_data.get("cve_id")
                    if not cve_id: continue
                    
                    advisory_id = f"ATL-{year}-{cve_id}"

                    # 1. Advisory Record
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("cve_summary"),
                        get_severity_from_score(raw_data.get("cve_severity")),
                        parse_date(raw_data.get("cve_publish_date")),
                        parse_date(raw_data.get("cve_last_updated_date")),
                        raw_data.get('atl_tracking_url') or raw_data.get('advisory_url')
                    )
                    
                    cve_key = (vendor_id, cve_id)

                    # 2. CVE Record
                    cves[cve_key] = (
                        vendor_id, cve_id,
                        None, # cwe_id
                        clean_text(raw_data.get("cve_details")),
                        get_severity_from_score(raw_data.get("cve_severity")),
                        raw_data.get("cve_severity"),
                        raw_data.get("cve_vector"),
                        None, None, # initial/latest release dates
                        raw_data.get('atl_tracking_url') or raw_data.get('advisory_url')
                    )
                    
                    # 3. Product Map
                    cve_product_maps[cve_key] = (vendor_id, cve_id, None, None)
                    
                    # 4. Map
                    advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")
                
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
# Jira_normal.py (Production Version)
import os
import re
import logging
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("jira_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Atlassian"

# --- Helper Functions (from your team's script) ---
def clean_text(text):
    if not text: return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(ts_str):
    if not ts_str: return None
    try:
        return datetime.fromisoformat(ts_str.replace("+0000", "+00:00")).date()
    except (ValueError, TypeError):
        return None

def get_severity_from_score(score_val):
    if score_val is None: return "Unknown"
    try:
        score = float(score_val)
        if score >= 9.0: return "Critical"
        if score >= 7.0: return "High"
        if score >= 4.0: return "Medium"
        if score > 0: return "Low"
        return "None"
    except (ValueError, TypeError):
        return "Unknown"

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
                    # Use a combination of fields to create a unique advisory ID
                    year = parse_date(raw_data.get('cve_publish_date')).year if parse_date(raw_data.get('cve_publish_date')) else datetime.now().year
                    cve_id = raw_data.get("cve_id")
                    if not cve_id: continue
                    advisory_id = f"ATL-{year}-{cve_id}"

                    # Advisory Record - severity is based on score
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("cve_summary"),
                        get_severity_from_score(raw_data.get("cve_severity")),
                        parse_date(raw_data.get("cve_publish_date")),
                        parse_date(raw_data.get("cve_last_updated_date")),
                        raw_data.get('atl_tracking_url') or raw_data.get('advisory_url')
                    )
                    
                    # CVE Record - specified columns are NULL
                    cves[(vendor_id, cve_id)] = (
                        vendor_id, cve_id,
                        None, # cwe_id
                        clean_text(raw_data.get("cve_details")),
                        get_severity_from_score(raw_data.get("cve_severity")),
                        raw_data.get("cve_severity"),
                        raw_data.get("cve_vector"),
                        None, None, # initial/latest release dates
                        raw_data.get('atl_tracking_url') or raw_data.get('advisory_url')
                    )
                    
                    # cve_product_map - recommendations is NULL
                    cve_product_maps[(vendor_id, cve_id)] = (vendor_id, cve_id, None, None)
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
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations=EXCLUDED.recommendations;
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
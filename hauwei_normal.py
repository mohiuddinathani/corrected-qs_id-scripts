# huawei_normal.py (Final Production Version)
import psycopg2, json, re, os, logging, sys
from datetime import datetime
from dotenv import load_dotenv
from psycopg2.extras import execute_values, Json
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    'dbname': os.getenv('DB_NAME'), 'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASS'), 
    'host': os.getenv('DB_HOST'), 'port': os.getenv('DB_PORT')
}
VENDOR_NAME = "Huawei"

# --- Helper Functions ---
def format_date(date_string):
    if not date_string or not isinstance(date_string, str): return None
    for fmt in ("%Y-%m-%d", "%b %d, %Y"):
        try: return datetime.strptime(date_string.strip(), fmt).date()
        except ValueError: pass
    return None

def to_numeric(score_str):
    if score_str is None: return None
    try: return float(score_str)
    except (ValueError, TypeError): return None

def calculate_severity(score):
    if score is None: return "Unknown"
    if 0.1 <= score <= 3.9: return "Low"
    if 4.0 <= score <= 6.9: return "Medium"
    if 7.0 <= score <= 8.9: return "High"
    if 9.0 <= score <= 10.0: return "Critical"
    return "Unknown"

def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                # Ensure Vendor Exists
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                # Fetch Staged Data
                cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE processed = FALSE AND vendor_name = %s;", (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info("No new Huawei records to process.")
                    return

                advisories, cves, cve_product_maps = {}, {}, {}
                advisory_cve_map = set()
                
                for staging_id, raw_data in tqdm(rows, desc="Parsing Staged Data"):
                    if not raw_data or not isinstance(raw_data, dict):
                        continue

                    advisory_id = raw_data.get("sa_number") or f"HUAWEI-SA-{staging_id}"
                    details = raw_data.get("details") if isinstance(raw_data.get("details"), dict) else {}

                    cve_list = raw_data.get("cve_ids") or [f"NOCVE-{advisory_id}"]
                    cvss_score_num = to_numeric(raw_data.get("cvss_base_score"))
                    final_severity = raw_data.get("severity") or calculate_severity(cvss_score_num)

                    # 1. Advisory
                    advisories[advisory_id] = (
                        advisory_id,
                        vendor_id,
                        raw_data.get("title"),
                        final_severity,
                        format_date(raw_data.get("initial_release_date")),
                        format_date(raw_data.get("last_release_date")),
                        raw_data.get("url"),
                    )

                    for cve_id in cve_list:
                        cve_key = (vendor_id, cve_id)
                        
                        # 2. CVE
                        cves[cve_key] = (
                            vendor_id,
                            cve_id,
                            None, # CWE
                            details.get("summary"),
                            final_severity,
                            cvss_score_num,
                            raw_data.get("cvss_vector"),
                            None, None, # Dates
                            raw_data.get("url"),
                        )

                        advisory_cve_map.add((advisory_id, vendor_id, cve_id))

                        # 3. Product Map
                        cve_product_maps[cve_key] = (
                            vendor_id,
                            cve_id,
                            None, # Affected products
                            details.get("software_versions_and_fixes"),
                        )

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
                        affected_products_cpe=EXCLUDED.affected_products_cpe, 
                        recommendations=EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))

                if advisory_cve_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) 
                        VALUES %s ON CONFLICT DO NOTHING;
                    """, list(advisory_cve_map))

                # Mark processed + Timestamp
                processed_ids = tuple(row[0] for row in rows)
                if processed_ids:
                    cur.execute("UPDATE vendor_staging_table SET processed = TRUE, processed_at = NOW() WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} staged records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()




'''
# huawei_normal.py (Final Production Version)
import psycopg2, json, re, os, logging, sys
from datetime import datetime
from dotenv import load_dotenv
from psycopg2.extras import execute_values, Json
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    'dbname': os.getenv('DB_NAME'), 'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASS'), # FIX: Corrected variable
    'host': os.getenv('DB_HOST'), 'port': os.getenv('DB_PORT')
}
VENDOR_NAME = "Huawei"

# --- Helper Functions (Copied from original script) ---
def format_date(date_string):
    if not date_string or not isinstance(date_string, str): return None
    for fmt in ("%Y-%m-%d", "%b %d, %Y"):
        try: return datetime.strptime(date_string.strip(), fmt).date()
        except ValueError: pass
    return None

def to_numeric(score_str):
    if score_str is None: return None
    try: return float(score_str)
    except (ValueError, TypeError): return None

def calculate_severity(score):
    if score is None: return "Unknown"
    if 0.1 <= score <= 3.9: return "Low"
    if 4.0 <= score <= 6.9: return "Medium"
    if 7.0 <= score <= 8.9: return "High"
    if 9.0 <= score <= 10.0: return "Critical"
    return "Unknown"

def main():
    logger.info(f"🚀 Starting Final {VENDOR_NAME} Processor (Pass 1)...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE processed = FALSE AND vendor_name = %s;", (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info("No new Huawei records to process.")
                    return

                advisories, cves, cve_product_maps = {}, {}, {}
                advisory_cve_map = set()
                
                for staging_id, raw_data in tqdm(rows, desc="Parsing Staged Data"):
                    # --- Force process everything, skip nothing ---
                    if not raw_data or not isinstance(raw_data, dict):
                        continue

                    advisory_id = raw_data.get("sa_number") or f"HUAWEI-SA-{staging_id}"
                    details = raw_data.get("details") if isinstance(raw_data.get("details"), dict) else {}

                    cve_list = raw_data.get("cve_ids") or [f"NOCVE-{advisory_id}"]
                    cvss_score_num = to_numeric(raw_data.get("cvss_base_score"))
                    final_severity = raw_data.get("severity") or calculate_severity(cvss_score_num)

                    advisories[advisory_id] = (
                        advisory_id,
                        vendor_id,
                        raw_data.get("title"),
                        final_severity,
                        format_date(raw_data.get("initial_release_date")),
                        format_date(raw_data.get("last_release_date")),
                        raw_data.get("url"),
                    )

                    for cve_id in cve_list:
                        cves[cve_id] = (
                            vendor_id,
                            cve_id,
                            None,
                            details.get("summary"),
                            final_severity,
                            cvss_score_num,
                            raw_data.get("cvss_vector"),
                            None,
                            None,
                            raw_data.get("url"),
                        )

                        advisory_cve_map.add((advisory_id, vendor_id, cve_id))

                        cve_product_maps[cve_id] = (
                            vendor_id,
                            cve_id,
                            None,
                            details.get("software_versions_and_fixes"),
                        )




                logger.info(f"Performing bulk inserts...")
                if advisories: execute_values(cur, "INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, latest_update_date=EXCLUDED.latest_update_date;", list(advisories.values()))
                if cves: execute_values(cur, "INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET description=COALESCE(EXCLUDED.description,cves.description), severity=COALESCE(EXCLUDED.severity,cves.severity), cvss_score=COALESCE(EXCLUDED.cvss_score,cves.cvss_score), latest_update_date=EXCLUDED.latest_update_date;", list(cves.values()))
                if advisory_cve_map: execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cve_map))
                if cve_product_maps: execute_values(cur, "INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET affected_products_cpe=EXCLUDED.affected_products_cpe, recommendations=EXCLUDED.recommendations;", list(cve_product_maps.values()))

                processed_ids = tuple(row[0] for row in rows)
                if processed_ids:
                    cur.execute("UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} staged records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()
'''    
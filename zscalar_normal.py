# Zscaler_normal.py (Final Production Version)
import os
import re
import logging
import psycopg2
import sys
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("zscaler_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Zscaler"

# --- Helper Functions ---
def clean_text(text):
    if not text: return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(date_str):
    if not date_str: return None
    for fmt in ("%B %d, %Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str.strip(), fmt).date()
        except (ValueError, TypeError):
            continue
    return None



def get_last_advisory_num(cur, date):
    cur.execute("SELECT advisory_id FROM advisories WHERE advisory_id LIKE %s ORDER BY advisory_id DESC LIMIT 1", (f"Zscaler-{date.strftime('%Y%m%d')}-%",))
    if last := cur.fetchone():
        try: return int(last[0].split('-')[-1])
        except (ValueError, IndexError): return 0
    return 0



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

                # Get Last ID Numbers for Sequence Generation
                cur.execute("""
                    SELECT to_char(initial_release_date, 'YYYY-MM-DD'), MAX(CAST(SPLIT_PART(advisory_id, '-', 3) AS INTEGER))
                    FROM advisories
                    WHERE vendor_id = %s AND advisory_id LIKE 'Zscaler-%%'
                    GROUP BY initial_release_date;
                """, (vendor_id,))    
                
                last_nums_by_date = {row[0]: row[1] for row in cur.fetchall() if row[0] is not None and row[1] is not None}

                advisories, cves, cve_product_maps, advisory_cve_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    created_at = parse_date(raw_data.get("created_at")) or datetime.now().date()
                    
                    date_key = created_at.strftime('%Y-%m-%d')
                    last_num = last_nums_by_date.get(date_key, 0)
                    new_num = last_num + 1
                    advisory_id = f"Zscaler-{created_at.strftime('%Y%m%d')}-{new_num:03d}"
                    last_nums_by_date[date_key] = new_num

                    # 1. Advisory Record
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("advisory_title"),
                        None, # Severity
                        created_at,
                        None, # latest_update_date
                        raw_data.get("advisory_url")
                    )
                    
                    cve_details = raw_data.get("cve_details", {}) or {}
                    for cve_id in raw_data.get("cve_ids", []):
                        detail = cve_details.get(cve_id, {})
                        
                        cve_key = (vendor_id, cve_id)
                        
                        # 2. CVE Record
                        cves[cve_key] = (
                            vendor_id, cve_id,
                            None, # cwe_id
                            clean_text(detail.get("description")),
                            clean_text(detail.get("severity")),
                            None, None, # cvss
                            None, None, # dates
                            detail.get("url")
                        )
                        
                        # 3. Product Map
                        cve_product_maps[cve_key] = (
                            vendor_id, cve_id, None, None
                        )
                        
                        # 4. Map
                        advisory_cve_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk database inserts...")
                
                # --- SQL LOGIC: Living Database + Sequence Sync ---

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) 
                        VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET 
                        title=EXCLUDED.title, 
                        initial_release_date=EXCLUDED.initial_release_date, 
                        latest_update_date=EXCLUDED.latest_update_date;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        description=COALESCE(EXCLUDED.description, cves.description), 
                        severity=COALESCE(EXCLUDED.severity, cves.severity), 
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
                logger.info(f"✅ Normalization complete for {len(rows)} records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()

'''
# Zscaler_normal.py (Production Version)
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
logger = logging.getLogger("zscaler_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Zscaler"

# --- Helper Functions ---
def clean_text(text):
    if not text: return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(date_str):
    if not date_str: return None
    for fmt in ("%B %d, %Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str.strip(), fmt).date()
        except (ValueError, TypeError):
            continue
    return None

def get_last_advisory_num(cur, date):
    cur.execute("SELECT advisory_id FROM advisories WHERE advisory_id LIKE %s ORDER BY advisory_id DESC LIMIT 1", (f"Zscaler-{date.strftime('%Y%m%d')}-%",))
    if last := cur.fetchone():
        try: return int(last[0].split('-')[-1])
        except (ValueError, IndexError): return 0
    return 0

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

                cur.execute("""
                    SELECT to_char(initial_release_date, 'YYYY-MM-DD'), MAX(CAST(SPLIT_PART(advisory_id, '-', 3) AS INTEGER))
                    FROM advisories
                    WHERE vendor_id = %s AND advisory_id LIKE 'Zscaler-%%'
                    GROUP BY initial_release_date;
                """, (vendor_id,))    


                last_nums_by_date = {row[0]: row[1] for row in cur.fetchall()}


                advisories, cves, cve_product_maps, advisory_cve_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    created_at = parse_date(raw_data.get("created_at")) or datetime.now().date()
                    
                    # Use the in-memory dictionary to track the last used number for this batch
                    date_key = created_at.strftime('%Y-%m-%d')
                    last_num = last_nums_by_date.get(date_key, 0)
                    new_num = last_num + 1
                    advisory_id = f"Zscaler-{created_at.strftime('%Y%m%d')}-{new_num:03d}"
                    last_nums_by_date[date_key] = new_num # Update the in-memory tracker for the next loop


                    
                    # Advisory Record - severity and latest_update_date are NULL
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("advisory_title"),
                        None, # Severity
                        created_at,
                        None, # latest_update_date
                        raw_data.get("advisory_url")
                    )
                    
                    cve_details = raw_data.get("cve_details", {}) or {}
                    for cve_id in raw_data.get("cve_ids", []):
                        detail = cve_details.get(cve_id, {})
                        
                        # CVE Record - specified columns are NULL
                        cves[(vendor_id, cve_id)] = (
                            vendor_id, cve_id,
                            None, # cwe_id
                            clean_text(detail.get("description")),
                            clean_text(detail.get("severity")),
                            None, # cvss_score
                            None, # cvss_vector
                            None, # initial_release_date
                            None, # latest_update_date
                            detail.get("url")
                        )
                        
                        cve_product_maps[(vendor_id, cve_id)] = (vendor_id, cve_id, None, None)
                        advisory_cve_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, initial_release_date=EXCLUDED.initial_release_date;
                    """, list(advisories.values()))
                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET description=EXCLUDED.description, severity=EXCLUDED.severity, reference_url=EXCLUDED.reference_url;
                    """, list(cves.values()))
                if cve_product_maps:
                    execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations=EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))
                if advisory_cve_map:
                    execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cve_map))

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
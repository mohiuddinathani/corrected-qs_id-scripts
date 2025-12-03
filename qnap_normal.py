# qnap_normal.py (Final Production Version - No tqdm)
import os
import logging
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from datetime import datetime
import sys

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("qnap_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "QNAP"

# --- Helper Functions ---
def parse_date(date_string):
    """Parses QNAP's common date formats into date objects."""
    if not date_string or date_string == 'Not Found': return None
    formats_to_try = ["%B %d, %Y", "%Y-%m-%d"]
    for fmt in formats_to_try:
        try:
            return datetime.strptime(date_string.strip(), fmt).date()
        except (ValueError, TypeError):
            continue
    return None

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

                logger.info(f"Parsing {len(rows)} {VENDOR_NAME} records...")
                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in rows:
                    advisory_id = raw_data.get("security_id")
                    if not advisory_id: continue

                    initial_date = parse_date(raw_data.get("release_date"))
                    latest_date = parse_date(raw_data.get("last_updated_date"))

                    # 1. Advisory Record
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("title"), raw_data.get("severity"),
                        initial_date, None, raw_data.get("url")
                    )

                    cve_list = raw_data.get("cve_identifiers", [])
                    if not cve_list: cve_list = [f"NOCVE-{advisory_id}"]

                    for cve_id in cve_list:
                        cve_key = (vendor_id, cve_id)

                        # 2. CVE Record
                        cves[cve_key] = (
                            vendor_id, cve_id,
                            None, # cwe_id
                            raw_data.get("summary"),
                            raw_data.get("severity"),
                            None, None, # cvss
                            None, None,
                            raw_data.get("url")
                        )
                        
                        # 3. Map
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))
                        
                        # 4. Product Map
                        cve_product_maps[cve_key] = (
                            vendor_id, cve_id, None, raw_data.get("recommendation")
                        )

                logger.info("Performing bulk database inserts...")
                
                # --- SQL LOGIC: Living Database + Sequence Sync ---

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) 
                        VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET 
                        title=EXCLUDED.title, 
                        severity=EXCLUDED.severity, 
                        latest_update_date=EXCLUDED.latest_update_date;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        description=COALESCE(EXCLUDED.description, cves.description), 
                        severity=COALESCE(EXCLUDED.severity, cves.severity), 
                        latest_update_date=EXCLUDED.latest_update_date;
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
                logger.info(f"✅ Normalization complete for {len(rows)} {VENDOR_NAME} records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        if 'conn' in locals() and conn: conn.rollback()

if __name__ == "__main__":
    main()

'''
# qnap_normal.py (Production Version - No tqdm)
import os
import logging
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from datetime import datetime

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("qnap_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "QNAP"

# --- Helper Functions ---
def parse_date(date_string):
    """Parses QNAP's common date formats into date objects."""
    if not date_string or date_string == 'Not Found': return None
    formats_to_try = ["%B %d, %Y", "%Y-%m-%d"]
    for fmt in formats_to_try:
        try:
            return datetime.strptime(date_string.strip(), fmt).date()
        except (ValueError, TypeError):
            continue
    logger.warning(f"Could not parse date: '{date_string}'")
    return None

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

                logger.info(f"Parsing {len(rows)} {VENDOR_NAME} records...")
                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in rows:
                    advisory_id = raw_data.get("security_id")
                    if not advisory_id: continue

                    initial_date = parse_date(raw_data.get("release_date"))
                    latest_date = parse_date(raw_data.get("last_updated_date"))

                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("title"), raw_data.get("severity"),
                        initial_date, None, raw_data.get("url")
                    )

                    cve_list = raw_data.get("cve_identifiers", [])
                    if not cve_list: cve_list = [f"NOCVE-{advisory_id}"]

                    for cve_id in cve_list:
                        cve_key = (vendor_id, cve_id)

                        cves[cve_key] = (
                            vendor_id, cve_id, None, raw_data.get("summary"),
                            raw_data.get("severity"), None, None,
                            None, None, raw_data.get("url")
                        )
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))
                        cve_product_maps[cve_key] = (
                            vendor_id, cve_id, None, raw_data.get("recommendation")
                        )

                logger.info("Performing bulk database inserts...")
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, latest_update_date=EXCLUDED.latest_update_date;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET description=EXCLUDED.description, severity=EXCLUDED.severity, latest_update_date=EXCLUDED.latest_update_date;
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
                    cur.execute("UPDATE vendor_staging_table SET processed = TRUE, processed_at = NOW() WHERE staging_id IN %s;", (processed_ids,))

                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} {VENDOR_NAME} records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        if 'conn' in locals() and conn: conn.rollback()

if __name__ == "__main__":
    main()
'''
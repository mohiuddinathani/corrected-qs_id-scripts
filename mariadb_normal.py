# mariadb_normal.py (Final Production Version)
import os
import logging
import psycopg2
import sys
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("mariadb_normalizer")
load_dotenv()

DB_CONFIG = {
    'dbname': os.getenv('DB_NAME'), 'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASS'), 'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT')
}
VENDOR_NAME = "MariaDB"

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
                cves, cve_product_maps = {}, {}

                for staging_id, raw_data in rows:
                    cve_id = raw_data.get('cve_id')
                    if not cve_id: continue
                    
                    cve_key = (vendor_id, cve_id)
                    
                    # 1. CVE Record
                    # MariaDB scraper returns None for most details, so we pass None
                    cves[cve_key] = (
                        vendor_id, cve_id, 
                        None, None, None, None, None, None, None, # cwe, desc, sev, cvss, vector, dates
                        raw_data.get('reference_url')
                    )
                    
                    # 2. Product Map
                    cve_product_maps[cve_key] = (
                        vendor_id, cve_id, 
                        None, # affected_products_cpe
                        raw_data.get('description', 'See reference URL for details.') # recommendations
                    )

                logger.info("Performing bulk database inserts...")
                
                # --- SQL LOGIC: Living Database + Sequence Sync ---

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        reference_url = EXCLUDED.reference_url,
                        description = COALESCE(EXCLUDED.description, cves.description);
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
                        recommendations = EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))

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
# mariadb_normal.py (Production Version)
import os
import logging
import psycopg2
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("mariadb_normalizer")
load_dotenv()

DB_CONFIG = {
    'dbname': os.getenv('DB_NAME'), 'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASS'), 'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT')
}
VENDOR_NAME = "MariaDB"

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
                cves, cve_product_maps = {}, {}

                for staging_id, raw_data in rows:
                    cve_id = raw_data.get('cve_id')
                    if not cve_id: continue
                    
                    cve_key = (vendor_id, cve_id)
                    cves[cve_key] = (
                        vendor_id, cve_id, 
                        None, None, None, None, None, None, None, # cwe, desc, sev, cvss, vector, dates are NULL
                        raw_data.get('reference_url')
                    )
                    
                    cve_product_maps[cve_key] = (
                        vendor_id, cve_id, None, # affected_products_cpe is NULL
                        raw_data.get('description', 'See reference URL for details.') # recommendations
                    )

                logger.info("Performing bulk database inserts...")
                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET reference_url = EXCLUDED.reference_url;
                    """, list(cves.values()))

                if cve_product_maps:
                    execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations = EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))

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
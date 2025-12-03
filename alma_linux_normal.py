# AlmaLinux_normal.py (Production Version - Corrected)
import os
import logging
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from datetime import datetime

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("almalinux_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "AlmaLinux"

# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                # Get or create vendor_id
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]
                
                # Fetch unprocessed staging data
                cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE vendor_name=%s AND processed=false", (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info(f"No new {VENDOR_NAME} records to process.")
                    return

                logger.info(f"Found {len(rows)} unprocessed advisories to normalize.")
                
                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in rows:
                    advisory_id = raw_data.get("advisory_id")
                    if not advisory_id: continue

                    publish_date_str = raw_data.get("publish_date")
                    publish_date = None
                    if publish_date_str:
                        try:
                            publish_date = datetime.fromisoformat(publish_date_str).date()
                        except ValueError:
                            logger.warning(f"Could not parse date for advisory {advisory_id}: {publish_date_str}")
                    
                    # Extract advisory-level info to apply to all its CVEs
                    advisory_summary = raw_data.get("summary")
                    advisory_severity = raw_data.get("severity")

                    # Aggregate data for advisories table
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, advisory_summary, advisory_severity,
                        publish_date, publish_date, raw_data.get("detail_url")
                    )

                    for cve_id in raw_data.get("cve_list", []):
                        cve_key = (vendor_id, cve_id)
                        
                        # Aggregate data for cves table
                        cves[cve_key] = (
                            vendor_id, cve_id,
                            None,                      # cwe_id (still missing)
                            advisory_summary,          # description (NOW POPULATED)
                            advisory_severity,         # severity (NOW POPULATED)
                            None,                      # cvss_score (still missing)
                            None,                      # cvss_vector (still missing)
                            publish_date,              # initial_release_date (NOW POPULATED)
                            publish_date,              # latest_update_date (NOW POPULATED)
                            f"https://access.redhat.com/security/cve/{cve_id}"
                        )
                        
                        # Aggregate data for mapping tables
                        cve_product_maps[cve_key] = (vendor_id, cve_id, None, None) # recommendations is still NULL
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk database inserts...")
                
                # 1. ADVISORIES: Full Upsert
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (
                            advisory_id, vendor_id, title, severity, 
                            initial_release_date, latest_update_date, advisory_url
                        ) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET 
                            title = EXCLUDED.title, 
                            severity = EXCLUDED.severity, 
                            latest_update_date = EXCLUDED.latest_update_date,
                            advisory_url = EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                # 2. CVES: Full Upsert (Updates Score, Vector, CWE, etc.)
                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (
                            vendor_id, cve_id, cwe_id, description, severity, 
                            cvss_score, cvss_vector, initial_release_date, 
                            latest_update_date, reference_url
                        ) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                            cwe_id = EXCLUDED.cwe_id,
                            description = EXCLUDED.description,
                            severity = EXCLUDED.severity,
                            cvss_score = EXCLUDED.cvss_score,
                            cvss_vector = EXCLUDED.cvss_vector,
                            initial_release_date = EXCLUDED.initial_release_date,
                            latest_update_date = EXCLUDED.latest_update_date,
                            reference_url = EXCLUDED.reference_url;
                    """, list(cves.values()))

                # 3. PRODUCT MAP: Sync Sequence + Update Details (Keep qs_id)
                if cve_product_maps:
                    # --- CRITICAL FIX: Sync the Sequence ---
                    # This ensures the next auto-generated qs_id is higher than any existing one.
                    cur.execute("""
                        SELECT setval('qs_id_seq', COALESCE((
                            SELECT MAX(SUBSTRING(qs_id FROM 4)::INTEGER) 
                            FROM cve_product_map
                        ), 0) + 1);
                    """)

                    # --- CRITICAL FIX: Update data without breaking qs_id ---
                    execute_values(cur, """
                        INSERT INTO cve_product_map (
                            vendor_id, cve_id, affected_products_cpe, recommendations
                        ) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                            affected_products_cpe = EXCLUDED.affected_products_cpe,
                            recommendations = EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))

                # 4. MAP TABLE: Simple Insert (Linkages rarely change)
                if advisory_cves_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) 
                        VALUES %s 
                        ON CONFLICT DO NOTHING;
                    """, list(advisory_cves_map))
                # Mark all processed rows in a single command
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
# AlmaLinux_normal.py (Production Version - Corrected)
import os
import logging
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from datetime import datetime

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("almalinux_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "AlmaLinux"

# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                # Get or create vendor_id
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]
                
                # Fetch unprocessed staging data
                cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE vendor_name=%s AND processed=false", (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info(f"No new {VENDOR_NAME} records to process.")
                    return

                logger.info(f"Found {len(rows)} unprocessed advisories to normalize.")
                
                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in rows:
                    advisory_id = raw_data.get("advisory_id")
                    if not advisory_id: continue

                    publish_date_str = raw_data.get("publish_date")
                    publish_date = None
                    if publish_date_str:
                        try:
                            publish_date = datetime.fromisoformat(publish_date_str).date()
                        except ValueError:
                            logger.warning(f"Could not parse date for advisory {advisory_id}: {publish_date_str}")
                    
                    # Extract advisory-level info to apply to all its CVEs
                    advisory_summary = raw_data.get("summary")
                    advisory_severity = raw_data.get("severity")

                    # Aggregate data for advisories table
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, advisory_summary, advisory_severity,
                        publish_date, publish_date, raw_data.get("detail_url")
                    )

                    for cve_id in raw_data.get("cve_list", []):
                        cve_key = (vendor_id, cve_id)
                        
                        # Aggregate data for cves table
                        cves[cve_key] = (
                            vendor_id, cve_id,
                            None,                      # cwe_id (still missing)
                            advisory_summary,          # description (NOW POPULATED)
                            advisory_severity,         # severity (NOW POPULATED)
                            None,                      # cvss_score (still missing)
                            None,                      # cvss_vector (still missing)
                            publish_date,              # initial_release_date (NOW POPULATED)
                            publish_date,              # latest_update_date (NOW POPULATED)
                            f"https://access.redhat.com/security/cve/{cve_id}"
                        )
                        
                        # Aggregate data for mapping tables
                        cve_product_maps[cve_key] = (vendor_id, cve_id, None, None) # recommendations is still NULL
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
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                            description = EXCLUDED.description,
                            severity = EXCLUDED.severity,
                            initial_release_date = EXCLUDED.initial_release_date,
                            latest_update_date = EXCLUDED.latest_update_date;
                    """, list(cves.values()))

                if cve_product_maps:
                    execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO NOTHING;
                    """, list(cve_product_maps.values()))

                if advisory_cves_map:
                    execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cves_map))

                # Mark all processed rows in a single command
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
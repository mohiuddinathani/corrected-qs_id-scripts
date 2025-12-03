# Firefox_normal.py (Final Production Version)
import os
import json
import psycopg2
import sys
import logging
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv
from datetime import datetime
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("firefox_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "host": os.getenv("DB_HOST"), 
    "port": os.getenv("DB_PORT"),
    "dbname": os.getenv("DB_NAME"), 
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS")
}
VENDOR_NAME = "Mozilla Firefox"

def parse_date(date_str):
    if not date_str: return None
    try:
        return datetime.strptime(date_str, "%B %d, %Y").date()
    except (ValueError, TypeError):
        return None

def main():
    logger.info(f"🚀 Starting Final {VENDOR_NAME} Processor...")
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
                    logger.info("No new Firefox records to process.")
                    return

                logger.info(f"Normalizing {len(rows)} new records...")
                advisories, cves, advisory_cve_maps, cve_product_maps = {}, {}, set(), {}

                for staging_id, raw_data in tqdm(rows, desc="Parsing Staged Data"):
                    data = raw_data
                    advisory_id = data.get("advisory_id")
                    if not advisory_id: continue

                    release_date = parse_date(data.get("announced_date"))
                    
                    # 1. Advisories
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, data.get("title"),
                        data.get("advisory_severity"), release_date,
                        release_date, # Use release date as last updated initially
                        data.get("link")
                    )

                    for cve in data.get("cves", []):
                        cve_id = cve.get("cve_id")
                        if not cve_id: continue
                        
                        cve_key = (vendor_id, cve_id)
                        
                        # 2. CVEs
                        cves[cve_key] = (
                            vendor_id, cve_id, 
                            None, # cwe_id
                            cve.get("description"),
                            data.get("advisory_severity"),
                            None, None, # No CVSS data from scraper
                            None, None, # dates
                            data.get("link")
                        )
                        
                        # 3. Map
                        advisory_cve_maps.add((advisory_id, vendor_id, cve_id))
                        
                        # 4. Product Map
                        recommendations = "Fixed in: " + ", ".join(data.get("fixed_in", [])) if data.get("fixed_in") else "See advisory URL."
                        cve_product_maps[cve_key] = (vendor_id, cve_id, None, recommendations)

                logger.info("Performing bulk database inserts...")
                
                # --- SQL LOGIC: Living Database + Sequence Sync ---

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) 
                        VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET 
                        title=EXCLUDED.title, 
                        severity=EXCLUDED.severity, 
                        initial_release_date=EXCLUDED.initial_release_date,
                        latest_update_date=EXCLUDED.latest_update_date,
                        advisory_url=EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        reference_url=EXCLUDED.reference_url,
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

                if advisory_cve_maps:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) 
                        VALUES %s ON CONFLICT DO NOTHING;
                    """, list(advisory_cve_maps))

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
# Firefox_normal.py (Final Production Version)
import os
import json
import psycopg2
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv
from datetime import datetime
import logging
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "host": os.getenv("DB_HOST"), "port": os.getenv("DB_PORT"),
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS")
}
VENDOR_NAME = "Mozilla Firefox"

def parse_date(date_str):
    if not date_str: return None
    try:
        return datetime.strptime(date_str, "%B %d, %Y").date()
    except (ValueError, TypeError):
        return None

def main():
    logger.info(f"🚀 Starting Final {VENDOR_NAME} Processor (Pass 1)...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE vendor_name=%s AND processed=false", (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info("No new Firefox records to process.")
                    return

                advisories, cves, advisory_cve_maps, cve_product_maps = {}, {}, set(), {}

                for staging_id, raw_data in tqdm(rows, desc="Parsing Staged Data"):
                    data = raw_data
                    advisory_id = data.get("advisory_id")
                    if not advisory_id: continue

                    release_date = parse_date(data.get("announced_date"))
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, data.get("title"),
                        data.get("advisory_severity"), release_date,
                        release_date, # Use release date as last updated
                        data.get("link")
                    )

                    for cve in data.get("cves", []):
                        cve_id = cve.get("cve_id")
                        if not cve_id: continue
                        
                        cves[cve_id] = (
                            vendor_id, cve_id, None, cve.get("description"),
                            data.get("advisory_severity"),
                            None, None, # No CVSS data from scraper
                            None, None,
                            data.get("link")
                        )
                        # --- THIS IS THE FIX: Use the correct plural variable name ---
                        advisory_cve_maps.add((advisory_id, vendor_id, cve_id))
                        
                        recommendations = "Fixed in: " + ", ".join(data.get("fixed_in", [])) if data.get("fixed_in") else "See advisory URL."
                        cve_product_maps[cve_id] = (vendor_id, cve_id, None, recommendations)

                logger.info("Performing bulk inserts...")
                if advisories: execute_values(cur, "INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, latest_update_date=EXCLUDED.latest_update_date;", list(advisories.values()))
                if cves: execute_values(cur, "INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET description=COALESCE(EXCLUDED.description, cves.description), severity=COALESCE(EXCLUDED.severity, cves.severity), latest_update_date=EXCLUDED.latest_update_date;", list(cves.values()))
                
                # --- THIS IS THE FIX: Use the correct plural variable name ---
                if advisory_cve_maps:
                    execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cve_maps))
                
                if cve_product_maps: execute_values(cur, "INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations=EXCLUDED.recommendations;", list(cve_product_maps.values()))

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
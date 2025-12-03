# Cisco_normal.py (Final Production Version)
import psycopg2
import os
import sys
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv
import logging
from tqdm import tqdm
from datetime import datetime

# --- Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    'dbname': os.getenv("DB_NAME"),
    'user': os.getenv("DB_USER"),
    'password': os.getenv("DB_PASS"), 
    'host': os.getenv("DB_HOST"),
    'port': os.getenv("DB_PORT")
}
VENDOR_NAME = "Cisco"

# --- Helper Function ---
def parse_date(date_string):
    if not date_string: return None
    try:
        return datetime.fromisoformat(date_string.replace('Z', '+00:00')).date()
    except (ValueError, TypeError):
        return None

def main():
    logger.info(f"🚀 Starting Final {VENDOR_NAME} Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cursor:
                # Ensure Vendor Exists
                cursor.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cursor.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cursor.fetchone()[0]

                # Fetch Staging Data
                cursor.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE processed = false AND vendor_name = %s;", (VENDOR_NAME,))
                rows = cursor.fetchall()
                if not rows:
                    logger.info("No new Cisco records to process.")
                    return

                # Initialize containers
                advisories, cves, cve_product_maps = {}, {}, {}
                advisory_cve_map = set()
                
                for staging_id, raw_data in tqdm(rows, desc="Parsing Staged Data"):
                    advisory = raw_data
                    advisory_id = advisory.get("advisoryId")
                    if not advisory_id: continue

                    # 1. Advisories Data
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, advisory.get("advisoryTitle"),
                        advisory.get("sir"), parse_date(advisory.get("firstPublished")),
                        parse_date(advisory.get("lastUpdated")), advisory.get("publicationUrl")
                    )

                    for cve_id in advisory.get("cves", []):
                        raw_score = advisory.get("cvssBaseScore")
                        try:
                            cvss_score = float(raw_score) if raw_score not in (None, "", "NA") else None
                        except (ValueError, TypeError):
                            cvss_score = None
                        
                        # 2. CVEs Data
                        # Note: Description and Severity are currently None in this parser, 
                        # so we will use COALESCE in SQL to avoid overwriting existing data with NULL.
                        cves[cve_id] = (
                            vendor_id, cve_id, advisory.get("cwe", [None])[0],
                            None, None, # Description, Severity
                            cvss_score, None,
                            None, # Initial Release
                            None, # Latest Update
                            advisory.get("publicationUrl")
                        )
                        
                        # 3. Mapping Data
                        advisory_cve_map.add((advisory_id ,vendor_id, cve_id))
                        
                        # 4. Product Map Data
                        cve_product_maps[cve_id] = (vendor_id, cve_id, None, None)

                logger.info(f"Performing bulk inserts for {len(advisories)} unique advisories and {len(cves)} unique CVEs...")
                
                # --- SQL LOGIC: Living Database + Sequence Sync ---

                if advisories:
                    execute_values(cursor, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                        VALUES %s ON CONFLICT (advisory_id) DO UPDATE SET
                        title = EXCLUDED.title, 
                        severity = EXCLUDED.severity, 
                        initial_release_date = EXCLUDED.initial_release_date,
                        latest_update_date = EXCLUDED.latest_update_date,
                        advisory_url = EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cursor, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
                        VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET
                        cwe_id = COALESCE(EXCLUDED.cwe_id, cves.cwe_id),
                        cvss_score = COALESCE(EXCLUDED.cvss_score, cves.cvss_score),
                        reference_url = EXCLUDED.reference_url,
                        -- Use COALESCE for fields we are passing as None to preserve existing data
                        description = COALESCE(EXCLUDED.description, cves.description), 
                        severity = COALESCE(EXCLUDED.severity, cves.severity);
                    """, list(cves.values()))

                if cve_product_maps:
                    # --- CRITICAL FIX: Sync the Sequence ---
                    cursor.execute("""
                        SELECT setval('qs_id_seq', COALESCE((
                            SELECT MAX(SUBSTRING(qs_id FROM 4)::INTEGER) 
                            FROM cve_product_map
                        ), 0) + 1);
                    """)

                    # --- CRITICAL FIX: Update data without breaking qs_id ---
                    execute_values(cursor, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations)
                        VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        recommendations = EXCLUDED.recommendations,
                        affected_products_cpe = EXCLUDED.affected_products_cpe;
                    """, list(cve_product_maps.values()))

                if advisory_cve_map:
                    execute_values(cursor, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) 
                        VALUES %s ON CONFLICT DO NOTHING;
                    """, list(advisory_cve_map))

                # Mark processed + Timestamp
                processed_ids = tuple(row[0] for row in rows)
                if processed_ids:
                    cursor.execute("UPDATE vendor_staging_table SET processed = TRUE, processed_at = NOW() WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} staged records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()


'''
# Cisco_normal.py (Final Production Version with De-duplication)
import psycopg2
import os
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv
import logging
from tqdm import tqdm
from datetime import datetime

# --- Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    'dbname': os.getenv("DB_NAME"),
    'user': os.getenv("DB_USER"),
    'password': os.getenv("DB_PASS"), 
    'host': os.getenv("DB_HOST"),
    'port': os.getenv("DB_PORT")
}
VENDOR_NAME = "Cisco"

# --- Helper Function ---
def parse_date(date_string):
    if not date_string: return None
    try:
        return datetime.fromisoformat(date_string.replace('Z', '+00:00')).date()
    except (ValueError, TypeError):
        return None

def main():
    logger.info(f"🚀 Starting Final {VENDOR_NAME} Processor (Pass 1)...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cursor:
                cursor.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cursor.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cursor.fetchone()[0]

                cursor.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE processed = false AND vendor_name = %s;", (VENDOR_NAME,))
                rows = cursor.fetchall()
                if not rows:
                    logger.info("No new Cisco records to process.")
                    return

                # --- THIS IS THE FIX: Use dictionaries for de-duplication ---
                advisories, cves, cve_product_maps = {}, {}, {}
                advisory_cve_map = set() # A set is already de-duplicated
                
                for staging_id, raw_data in tqdm(rows, desc="Parsing Staged Data"):
                    advisory = raw_data
                    advisory_id = advisory.get("advisoryId")
                    if not advisory_id: continue

                    # Using the advisory_id as the key de-duplicates advisories
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, advisory.get("advisoryTitle"),
                        advisory.get("sir"), parse_date(advisory.get("firstPublished")),
                        parse_date(advisory.get("lastUpdated")), advisory.get("publicationUrl")
                    )

                    for cve_id in advisory.get("cves", []):
                        raw_score = advisory.get("cvssBaseScore")
                        try:
                            cvss_score = float(raw_score) if raw_score not in (None, "", "NA") else None
                        except (ValueError, TypeError):
                            cvss_score = None
                        
                        # Using cve_id as the key de-duplicates CVEs. "Last write wins".
                        cves[cve_id] = (
                            vendor_id, cve_id, advisory.get("cwe", [None])[0],
                            None, None,
                            cvss_score, None,
                            None,
                            None,
                            advisory.get("publicationUrl")
                        )
                        advisory_cve_map.add((advisory_id ,vendor_id, cve_id))
                        cve_product_maps[cve_id] = (vendor_id, cve_id, None, None)

                logger.info(f"Performing bulk inserts for {len(advisories)} unique advisories and {len(cves)} unique CVEs...")
                
                # Convert dictionary values to lists for execute_values
                if advisories:
                    execute_values(cursor, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                        VALUES %s ON CONFLICT (advisory_id) DO UPDATE SET
                        title = EXCLUDED.title, severity = EXCLUDED.severity, latest_update_date = EXCLUDED.latest_update_date;
                    """, list(advisories.values()))
                if cves:
                    execute_values(cursor, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
                        VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET
                        cwe_id = COALESCE(EXCLUDED.cwe_id, cves.cwe_id), severity = COALESCE(EXCLUDED.severity, cves.severity),
                        cvss_score = COALESCE(EXCLUDED.cvss_score, cves.cvss_score), cvss_vector = COALESCE(EXCLUDED.cvss_vector, cves.cvss_vector),
                        latest_update_date = EXCLUDED.latest_update_date;
                    """, list(cves.values()))
                if advisory_cve_map:
                    execute_values(cursor, "INSERT INTO advisory_cves_map (advisory_id,vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cve_map))
                if cve_product_maps:
                    execute_values(cursor, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations)
                        VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations = EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))

                processed_ids = tuple(row[0] for row in rows)
                if processed_ids:
                    cursor.execute("UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} staged records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()
'''
# Cloudflare_normal.py (Final Production Version)
import os
import logging
import sys
import psycopg2
from psycopg2.extras import DictCursor, execute_values
from dotenv import load_dotenv
from tqdm import tqdm
from datetime import datetime

# --- Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)
load_dotenv()

# --- Configuration ---
# Constructing connection string from env vars
DB_CONN_STRING = (
    f"dbname='{os.getenv('DB_NAME')}' "
    f"user='{os.getenv('DB_USER')}' "
    f"host='{os.getenv('DB_HOST')}' "
    f"password='{os.getenv('DB_PASS')}' "
    f"port='{os.getenv('DB_PORT')}'"
)
VENDOR_NAME = "Cloudflare"

def parse_date(date_string):
    if not date_string: return None
    try:
        # Handles formats like "Dec 21, 2023"
        return datetime.strptime(date_string, "%b %d, %Y").date()
    except (ValueError, TypeError):
        return None

def main():
    logger.info(f"🚀 Starting Final {VENDOR_NAME} Processor...")
    try:
        with psycopg2.connect(DB_CONN_STRING) as conn:
            with conn.cursor(cursor_factory=DictCursor) as cursor:
                # Ensure Vendor Exists
                cursor.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cursor.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cursor.fetchone()['vendor_id']

                # Fetch Staging Data
                cursor.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE vendor_name = %s AND processed = FALSE;", (VENDOR_NAME,))
                staged_records = cursor.fetchall()
                if not staged_records:
                    logger.info("No new records to process.")
                    return

                # --- Initialize Containers (Using Dicts for Deduplication) ---
                advisories = {}
                cves = {}
                cve_product_maps = {}
                advisory_cve_maps = set()
                
                for record in tqdm(staged_records, desc="Parsing Staged Data"):
                    raw_data = record['raw_data']
                    
                    advisory_id = raw_data.get("id")
                    if not advisory_id: continue

                    # 1. Advisories
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("title"),
                        raw_data.get("severity"), parse_date(raw_data.get("published_display")),
                        parse_date(raw_data.get("published_display")), 
                        raw_data.get("url")
                    )

                    cve_id = raw_data.get("cve_id")
                    if cve_id:
                        severity_details = raw_data.get("severity_details", {})
                        
                        # Safely convert cvss_score to float
                        try:
                            cvss_score = float(severity_details.get("cvss_score"))
                        except (ValueError, TypeError):
                            cvss_score = None
                        
                        # 2. CVEs
                        cve_key = (vendor_id, cve_id)
                        cves[cve_key] = (
                            vendor_id, cve_id, raw_data.get("cwe_id"), raw_data.get("description"),
                            severity_details.get("level"), cvss_score,
                            severity_details.get("cvss_vector"),
                            ",".join(raw_data.get("references", [])) or None
                        )
                        
                        # 3. Map
                        advisory_cve_maps.add((advisory_id, vendor_id, cve_id))
                        
                        # 4. Product Map
                        # Recommendations/Products are often null in this source, but we ensure the record exists
                        cve_product_maps[cve_key] = (
                            vendor_id, cve_id,
                            None, # Affected products (JSONB)
                            raw_data.get("recommendations") 
                        )

                logger.info(f"Performing bulk inserts for {len(advisories)} advisories...")
                
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
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, reference_url)
                        VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET
                        cwe_id = EXCLUDED.cwe_id, 
                        description = EXCLUDED.description, 
                        severity = EXCLUDED.severity,
                        cvss_score = EXCLUDED.cvss_score, 
                        cvss_vector = EXCLUDED.cvss_vector, 
                        reference_url = EXCLUDED.reference_url;
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

                if advisory_cve_maps:
                    execute_values(cursor, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) 
                        VALUES %s ON CONFLICT DO NOTHING;
                    """, list(advisory_cve_maps))

                # Mark processed + Timestamp
                processed_ids = tuple(rec['staging_id'] for rec in staged_records)
                if processed_ids:
                    cursor.execute("UPDATE vendor_staging_table SET processed = TRUE, processed_at = NOW() WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(staged_records)} staged records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()



'''
# Cloudflare_normal.py (Final Production Version)
import os
import logging
import psycopg2
from psycopg2.extras import DictCursor, execute_values, Json
from dotenv import load_dotenv
from tqdm import tqdm
from datetime import datetime

# --- Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
load_dotenv()

# --- Configuration ---
DB_CONN_STRING = (
    f"dbname='{os.getenv('DB_NAME')}' "
    f"user='{os.getenv('DB_USER')}' "
    f"host='{os.getenv('DB_HOST')}' "
    f"password='{os.getenv('DB_PASS')}' "
    f"port='{os.getenv('DB_PORT')}'"
)
VENDOR_NAME = "Cloudflare"

def parse_date(date_string):
    if not date_string: return None
    try:
        # Handles formats like "Dec 21, 2023"
        return datetime.strptime(date_string, "%b %d, %Y").date()
    except (ValueError, TypeError):
        return None

def main():
    logger.info(f"🚀 Starting Final {VENDOR_NAME} Processor (Pass 1)...")
    try:
        with psycopg2.connect(DB_CONN_STRING) as conn:
            with conn.cursor(cursor_factory=DictCursor) as cursor:
                cursor.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cursor.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cursor.fetchone()['vendor_id']

                cursor.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE vendor_name = %s AND processed = FALSE;", (VENDOR_NAME,))
                staged_records = cursor.fetchall()
                if not staged_records:
                    logger.info("No new records to process.")
                    return

                # --- REFACTOR: Collect all data into lists first for bulk processing ---
                advisories, cves, advisory_cve_maps, cve_product_maps = [], [], [], []
                
                for record in tqdm(staged_records, desc="Parsing Staged Data"):
                    raw_data = record['raw_data']
                    
                    advisory_id = raw_data.get("id")
                    if not advisory_id: continue

                    advisories.append((
                        advisory_id, vendor_id, raw_data.get("title"),
                        raw_data.get("severity"), parse_date(raw_data.get("published_display")),
                        parse_date(raw_data.get("published_display")), 
                        raw_data.get("url")
                    ))

                    cve_id = raw_data.get("cve_id")
                    if cve_id:
                        severity_details = raw_data.get("severity_details", {})
                        
                        # Safely convert cvss_score to float
                        cvss_score = None
                        try:
                            cvss_score = float(severity_details.get("cvss_score"))
                        except (ValueError, TypeError):
                            cvss_score = None
                        
                        cves.append((
                            vendor_id, cve_id, raw_data.get("cwe_id"), raw_data.get("description"),
                            severity_details.get("level"), cvss_score,
                            severity_details.get("cvss_vector"),
                            ",".join(raw_data.get("references", [])) or None
                        ))
                        
                        advisory_cve_maps.append((advisory_id, vendor_id, cve_id))
                        
                        # The scraper doesn't provide these, so they will be NULL
                        cve_product_maps.append((
                            vendor_id, cve_id,
                            None, # Will be null
                            raw_data.get("recommendations")              # Will be null
                        ))

                # --- REFACTOR: Perform a few, high-performance bulk inserts at the end ---
                logger.info(f"Performing bulk inserts for {len(advisories)} advisories...")
                if advisories:
                    execute_values(cursor, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                        VALUES %s ON CONFLICT (advisory_id) DO UPDATE SET
                        title = EXCLUDED.title, severity = EXCLUDED.severity, initial_release_date = EXCLUDED.initial_release_date;
                    """, advisories)

                if cves:
                    execute_values(cursor, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, reference_url)
                        VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET
                        cwe_id = EXCLUDED.cwe_id, description = EXCLUDED.description, severity = EXCLUDED.severity,
                        cvss_score = EXCLUDED.cvss_score, cvss_vector = EXCLUDED.cvss_vector, reference_url = EXCLUDED.reference_url;
                    """, cves)

                if advisory_cve_maps:
                    execute_values(cursor, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", advisory_cve_maps)

                if cve_product_maps:
                    execute_values(cursor, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations)
                        VALUES %s ON CONFLICT (vendor_id, cve_id) DO NOTHING;
                    """, cve_product_maps)

                processed_ids = tuple(rec['staging_id'] for rec in staged_records)
                if processed_ids:
                    cursor.execute("UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Pass 1 complete. Ingested data from {len(staged_records)} Cloudflare records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()
'''
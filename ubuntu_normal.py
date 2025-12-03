# ubuntu_processor.py (Final Hardened Version v2 - Pass 1)
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
DB_CONN_STRING = (
    f"dbname='{os.getenv('DB_NAME')}' "
    f"user='{os.getenv('DB_USER')}' "
    f"host='{os.getenv('DB_HOST')}' "
    f"password='{os.getenv('DB_PASS')}' "
    f"port='{os.getenv('DB_PORT')}'"
)
VENDOR_NAME = "Ubuntu"

def parse_date(date_string):
    if not date_string: return None
    try: return datetime.fromisoformat(date_string.replace('Z', '+00:00')).date()
    except (ValueError, TypeError): return None

def main():
    logger.info(f"🚀 Starting Final {VENDOR_NAME} Processor (Pass 1)...")
    try:
        with psycopg2.connect(DB_CONN_STRING) as conn:
            with conn.cursor(cursor_factory=DictCursor) as cursor:
                # Ensure Vendor Exists
                cursor.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cursor.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cursor.fetchone()['vendor_id']
                
                # Fetch Staging Data
                cursor.execute("SELECT staging_id, raw_data, source_url FROM vendor_staging_table WHERE vendor_name = %s AND processed = FALSE;", (VENDOR_NAME,))
                staged_records = cursor.fetchall()
                if not staged_records:
                    logger.info("No new records to process.")
                    return

                advisories, cves, advisory_cve_maps, cve_product_maps = {}, {}, set(), {}
                
                for record in tqdm(staged_records, desc="Parsing Vendor Data"):
                    data = record['raw_data']
                    cve_id = data.get('id')
                    if not cve_id: continue

                    notes_list = data.get('notes', [])
                    advisory_title = notes_list[0].get('title') if notes_list else f"Ubuntu Security Notice for {cve_id}"
                    
                    advisory_id = f"USN-{cve_id}"
                    
                    # 1. Advisory
                    advisories[advisory_id] = (
                        advisory_id, vendor_id,
                        advisory_title,
                        data.get('priority'),
                        parse_date(data.get('published')),
                        parse_date(data.get('updated_at')),
                        record['source_url']
                    )
                    
                    # --- Safely navigate the nested impact structure ---
                    impact_node = data.get('impact')
                    base_metric_node = impact_node.get('baseMetricV3') if impact_node else None
                    cvss_node = base_metric_node.get('cvssV3') if base_metric_node else None
                    impact = cvss_node if cvss_node else {} # Ensure 'impact' is always a dictionary
                    
                    # 2. CVE
                    cves[cve_id] = (
                        vendor_id,
                        cve_id, None,
                        data.get('description'),
                        impact.get('baseSeverity'),
                        impact.get('baseScore'),
                        impact.get('vectorString'),
                        parse_date(data.get('published')),
                        parse_date(data.get('updated_at')),
                        record['source_url']
                    )
                    
                    # 3. Map
                    advisory_cve_maps.add((advisory_id, vendor_id, cve_id))
                    
                    # 4. Product Map
                    cve_product_maps[cve_id] = (vendor_id, cve_id, None, None)
                        
                logger.info(f"Performing bulk inserts for {len(cves)} CVEs and {len(advisories)} advisories...")
                
                # --- SQL LOGIC: Living Database + Sequence Sync ---

                if advisories:
                    execute_values(cursor, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) 
                        VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET 
                        title = excluded.title, 
                        severity = excluded.severity, 
                        latest_update_date = excluded.latest_update_date;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cursor, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        cwe_id = COALESCE(excluded.cwe_id, cves.cwe_id), 
                        description = COALESCE(excluded.description, cves.description), 
                        severity=COALESCE(excluded.severity, cves.severity), 
                        cvss_score = COALESCE(excluded.cvss_score, cves.cvss_score), 
                        cvss_vector = COALESCE(excluded.cvss_vector, cves.cvss_vector), 
                        latest_update_date = excluded.latest_update_date;
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
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        recommendations = excluded.recommendations;
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
                logger.info(f"✅ Pass 1 complete. Ingested data for {len(cves)} unique CVEs.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()

'''
# ubuntu_processor.py (Final Hardened Version v2 - Pass 1)
import os
import logging
import psycopg2
from psycopg2.extras import DictCursor, execute_values
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
VENDOR_NAME = "Ubuntu"

def parse_date(date_string):
    if not date_string: return None
    try: return datetime.fromisoformat(date_string.replace('Z', '+00:00')).date()
    except (ValueError, TypeError): return None

def main():
    logger.info(f"🚀 Starting Final {VENDOR_NAME} Processor (Pass 1)...")
    try:
        with psycopg2.connect(DB_CONN_STRING) as conn:
            with conn.cursor(cursor_factory=DictCursor) as cursor:
                cursor.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cursor.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cursor.fetchone()['vendor_id']
                
                cursor.execute("SELECT staging_id, raw_data, source_url FROM vendor_staging_table WHERE vendor_name = %s AND processed = FALSE;", (VENDOR_NAME,))
                staged_records = cursor.fetchall()
                if not staged_records:
                    logger.info("No new records to process.")
                    return

                advisories, cves, advisory_cve_maps, cve_product_maps = {}, {}, set(), {}
                
                for record in tqdm(staged_records, desc="Parsing Vendor Data"):
                    data = record['raw_data']
                    cve_id = data.get('id')
                    if not cve_id: continue

                    notes_list = data.get('notes', [])
                    advisory_title = notes_list[0].get('title') if notes_list else f"Ubuntu Security Notice for {cve_id}"
                    
                    advisory_id = f"USN-{cve_id}"
                    advisories[advisory_id] = (
                        advisory_id, vendor_id,
                        advisory_title,
                        data.get('priority'),
                        parse_date(data.get('published')),
                        parse_date(data.get('updated_at')),
                        record['source_url']
                    )
                    
                    # --- THIS IS THE FIX: Safely navigate the nested impact structure ---
                    impact_node = data.get('impact')
                    base_metric_node = impact_node.get('baseMetricV3') if impact_node else None
                    cvss_node = base_metric_node.get('cvssV3') if base_metric_node else None
                    impact = cvss_node if cvss_node else {} # Ensure 'impact' is always a dictionary
                    
                    cves[cve_id] = (
                        vendor_id,
                        cve_id, None,
                        data.get('description'),
                        impact.get('baseSeverity'),
                        impact.get('baseScore'),
                        impact.get('vectorString'),
                        parse_date(data.get('published')),
                        parse_date(data.get('updated_at')),
                        record['source_url']
                    )
                    advisory_cve_maps.add((advisory_id, vendor_id, cve_id))
                    cve_product_maps[cve_id] = (vendor_id, cve_id, None, None)
                        
                logger.info(f"Performing bulk inserts for {len(cves)} CVEs and {len(advisories)} advisories...")
                if advisories: execute_values(cursor, "INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s ON CONFLICT (advisory_id) DO UPDATE SET title = excluded.title, severity = excluded.severity, latest_update_date = excluded.latest_update_date;", list(advisories.values()))
                if cves: execute_values(cursor, "INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET cwe_id = COALESCE(excluded.cwe_id, cves.cwe_id), description = COALESCE(excluded.description, cves.description), severity=COALESCE(excluded.severity, cves.severity), cvss_score = COALESCE(excluded.cvss_score, cves.cvss_score), cvss_vector = COALESCE(excluded.cvss_vector, cves.cvss_vector), latest_update_date = excluded.latest_update_date;", list(cves.values()))
                if advisory_cve_maps: execute_values(cursor, "INSERT INTO advisory_cves_map (advisory_id, vendor_id,  cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cve_maps))
                if cve_product_maps:
                    execute_values(cursor, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations = excluded.recommendations;
                    """, [value for value in cve_product_maps.values()])

                processed_ids = tuple(rec['staging_id'] for rec in staged_records)
                if processed_ids: cursor.execute("UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;", (processed_ids,))
                conn.commit()
                logger.info(f"✅ Pass 1 complete. Ingested data for {len(cves)} unique CVEs.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()
'''
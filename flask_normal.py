# Flask_normal.py (Final Production Version)
import os
import re
import logging
import json
import psycopg2
import sys
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("flask_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Flask"

# --- Helper Functions ---
def clean_text(text):
    if not text: return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(date_str):
    if not date_str: return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00")).date()
    except (ValueError, TypeError):
        return None

def safe_numeric(score_str):
    if not score_str: return None
    try:
        return float(score_str)
    except (ValueError, TypeError):
        return None

def extract_cwe_id(raw_data):
    """Extract CWE ID safely."""
    if not isinstance(raw_data, dict):
        return None
    return raw_data.get("cwe_id")

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
                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    # Parse JSON if needed
                    if isinstance(raw_data, str):
                        try:
                            raw_data = json.loads(raw_data)
                        except Exception as e:
                            logger.error(f"JSON decode error for ID {staging_id}: {e}")
                            continue
                        
                    if not isinstance(raw_data, dict):
                        continue
                    
                    advisory_id = raw_data.get("ghsa_id")
                    if not advisory_id: 
                        continue

                    # Extract details
                    cwe_id = extract_cwe_id(raw_data)
                    
                    # 1. Advisories
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("advisory_title"),
                        raw_data.get("severity"),
                        parse_date(raw_data.get("date_published")),
                        None, # Latest update date
                        raw_data.get("url")
                    )

                    cve_id = raw_data.get("cve_id")
                    if cve_id and cve_id.lower() not in ['n/a', 'no known cve', 'none']:
                        cve_key = (vendor_id, cve_id)
                        
                        # 2. CVEs
                        cves[cve_key] = (
                            vendor_id, 
                            cve_id,
                            cwe_id,
                            clean_text(raw_data.get("description")),
                            raw_data.get("severity"),
                            safe_numeric(raw_data.get("cvss_score")),
                            raw_data.get("cvss_vector"),
                            None, None,
                            raw_data.get("url")
                        )
                        
                        # 3. Product Map
                        recommendations = f"Affected Versions: {raw_data.get('affected_versions', 'N/A')}. Patched Versions: {raw_data.get('patched_versions', 'N/A')}."
                        cve_product_maps[cve_key] = (
                            vendor_id, cve_id, None, clean_text(recommendations)
                        )
                        
                        # 4. Map
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

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
                        latest_update_date=EXCLUDED.latest_update_date;
                        advisory_url=EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        cwe_id=EXCLUDED.cwe_id, 
                        cvss_score=EXCLUDED.cvss_score, 
                        cvss_vector=EXCLUDED.cvss_vector, 
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

if __name__ == "__main__":
    main()



'''
# Flask_normal.py (Production Version)
import os
import re
import logging
import json
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("flask_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Flask"

# --- Helper Functions ---
def clean_text(text):
    if not text: return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(date_str):
    if not date_str: return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00")).date()
    except (ValueError, TypeError):
        return None

def safe_numeric(score_str):
    if not score_str: return None
    try:
        return float(score_str)
    except (ValueError, TypeError):
        return None

# --- First, improve the extract_cwe_id function ---
def extract_cwe_id(raw_data):
    """Extract CWE ID with logging for debugging"""
    if not isinstance(raw_data, dict):
        logger.warning(f"raw_data is not a dict: {type(raw_data)}")
        return None
    
    # Try multiple ways to get CWE ID
    cwe_id = raw_data.get("cwe_id")
    if cwe_id:
        logger.info(f"Found CWE ID: {cwe_id}")
        return cwe_id
    
    # If no CWE ID found
    logger.warning("No CWE ID found in raw data")
    return None

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
                    logger.info(f"Processing staging_id: {staging_id}")
    
    # Parse JSON if needed
                    if isinstance(raw_data, str):
                        try:
                            raw_data = json.loads(raw_data)
                            logger.info("Successfully parsed JSON data")
                        except Exception as e:
                            logger.error(f"JSON decode error: {e}")
                            continue
                        
                    if not isinstance(raw_data, dict):
                        logger.warning(f"Skipping non-dict raw_data for staging_id={staging_id}")
                        continue
                    
                    advisory_id = raw_data.get("ghsa_id")
                    if not advisory_id: 
                        continue

                    # Extract CWE ID once
                    cwe_id = extract_cwe_id(raw_data)
                    
                    # Process advisory data
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("advisory_title"),
                        raw_data.get("severity"),
                        parse_date(raw_data.get("date_published")),
                        None,
                        raw_data.get("url")
                    )

                    cve_id = raw_data.get("cve_id")
                    if cve_id and cve_id.lower() not in ['n/a', 'no known cve']:
                        # Use the previously extracted cwe_id
                        cves[(vendor_id, cve_id)] = (
                            vendor_id, 
                            cve_id,
                            cwe_id,  # Use the extracted CWE ID
                            clean_text(raw_data.get("description")),
                            raw_data.get("severity"),
                            safe_numeric(raw_data.get("cvss_score")),
                            raw_data.get("cvss_vector"),
                            None, None,
                            raw_data.get("url")
                        )
                
                        logger.info(f"Total CVEs processed: {len(cves)}")
                        for (vid, cid), cve_data in cves.items():
                            logger.info(f"CVE: {cid}, CWE: {cve_data[2]}")


                        recommendations = f"Affected Versions: {raw_data.get('affected_versions', 'N/A')}. Patched Versions: {raw_data.get('patched_versions', 'N/A')}."
                        cve_product_maps[(vendor_id, cve_id)] = (
                            vendor_id, cve_id, None, clean_text(recommendations)
                        )
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, latest_update_date=EXCLUDED.latest_update_date;
                    """, list(advisories.values()))
                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET
                            cwe_id = EXCLUDED.cwe_id,
                            description = EXCLUDED.description,
                            severity = EXCLUDED.severity,
                            cvss_score = EXCLUDED.cvss_score,
                            cvss_vector = EXCLUDED.cvss_vector,
                            reference_url = EXCLUDED.reference_url;
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


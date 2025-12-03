# nodejs_normal.py (Production Version)
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
logger = logging.getLogger("nodejs_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Node.js"

# --- Helper Functions ---
def clean_text(text):
    if not text: return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(date_str):
    if not date_str: return None
    try:
        return datetime.strptime(date_str.strip(), "%B %d, %Y").date()
    except (ValueError, TypeError):
        return None

def find_cves_in_text(text_blob):
    return sorted(list(set(re.findall(r"CVE-\d{4}-\d{4,7}", str(text_blob or ""), re.IGNORECASE))))

def calculate_severity_from_text(text):
    """Derives the highest severity level from advisory content."""
    if not text: return None
    text = text.lower()
    if 'critical' in text: return 'Critical'
    if 'high' in text: return 'High'
    if 'medium' in text: return 'Medium'
    if 'low' in text: return 'Low'
    return 'Unknown'

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

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()
                advisory_counter = 0

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    year = datetime.now().year
                    if pub_date := parse_date(raw_data.get("last_updated")): year = pub_date.year
                    advisory_counter += 1
                    advisory_id = f"NODEJS-{year}-{advisory_counter:03d}"

                    # Try to determine severity from text content
                    content_text = " ".join(
                        item.get("text", "") for item in raw_data.get("content", []) if isinstance(item, dict)
                    )
                    severity = calculate_severity_from_text(content_text)

                    # 1. Advisory
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("title"),
                        severity,
                        None, # initial_release_date
                        parse_date(raw_data.get("last_updated")),
                        raw_data.get("url")
                    )

                    cve_ids = find_cves_in_text(str(raw_data.get("content", [])))
                    if not cve_ids: continue

                    for cve_id in cve_ids:
                        cve_key = (vendor_id, cve_id)
                        
                        # 2. CVE Record
                        cves[cve_key] = (
                            vendor_id, cve_id,
                            None, # cwe_id
                            raw_data.get("title"), # description
                            severity, None, None,  # severity, cvss_score, cvss_vector
                            None, None,
                            raw_data.get("url")
                        )

                        # 3. Product Map
                        cve_product_maps[cve_key] = (vendor_id, cve_id, None, "See advisory URL for patching details.")
                        
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
                        latest_update_date=EXCLUDED.latest_update_date,
                        advisory_url=EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE
                        SET description = COALESCE(EXCLUDED.description, cves.description),
                            severity = COALESCE(EXCLUDED.severity, cves.severity),
                            reference_url = EXCLUDED.reference_url;
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

if __name__ == "__main__":
    main()

'''
# nodejs_normal.py (Production Version)
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
logger = logging.getLogger("nodejs_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Node.js"

# --- Helper Functions ---
def clean_text(text):
    if not text: return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(date_str):
    if not date_str: return None
    try:
        return datetime.strptime(date_str.strip(), "%B %d, %Y").date()
    except (ValueError, TypeError):
        return None

def find_cves_in_text(text_blob):
    return sorted(list(set(re.findall(r"CVE-\d{4}-\d{4,7}", str(text_blob or ""), re.IGNORECASE))))

def calculate_severity_from_text(text):
    """Derives the highest severity level from advisory content."""
    if not text: return None
    text = text.lower()
    if 'critical' in text: return 'Critical'
    if 'high' in text: return 'High'
    if 'medium' in text: return 'Medium'
    if 'low' in text: return 'Low'
    return 'Unknown'

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

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()
                advisory_counter = 0

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    year = datetime.now().year
                    if pub_date := parse_date(raw_data.get("last_updated")): year = pub_date.year
                    advisory_counter += 1
                    advisory_id = f"NODEJS-{year}-{advisory_counter:03d}"

                    # Try to determine severity from text content
                    content_text = " ".join(
                        item.get("text", "") for item in raw_data.get("content", []) if isinstance(item, dict)
                    )
                    severity = calculate_severity_from_text(content_text)

                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("title"),
                        severity,
                        None, # initial_release_date
                        parse_date(raw_data.get("last_updated")),
                        raw_data.get("url")
                    )

                    
                    cve_ids = find_cves_in_text(str(raw_data.get("content", [])))
                    if not cve_ids: continue

                    for cve_id in cve_ids:
                        # CVE Record - specified columns are NULL
                        cves[(vendor_id, cve_id)] = (
                            vendor_id, cve_id,
                            None, # cwe_id
                            raw_data.get("title"), # description
                            severity, None, None,  # severity, cvss_score, cvss_vector
                            None, None,
                            raw_data.get("url")
                        )

                        cve_product_maps[(vendor_id, cve_id)] = (vendor_id, cve_id, None, "See advisory URL for patching details.")
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, latest_update_date=EXCLUDED.latest_update_date;
                    """, list(advisories.values()))
                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE
                        SET description = EXCLUDED.description,
                            severity = EXCLUDED.severity,
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
# Django_normal.py (Final Production Version)
import os
import re
import logging
import psycopg2
import sys
from psycopg2.extras import execute_values, Json
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm
from urllib.parse import urlparse
from typing import Optional

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("django_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Django"

# --- Helper Functions ---
def clean_text(text):
    if not text: return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(date_string: str) -> Optional[datetime.date]:
    if not date_string: return None
    try:
        return datetime.strptime(date_string, "%B %d, %Y").date()
    except (ValueError, TypeError):
        return None

def generate_advisory_id(url: str) -> str:
    if not url: return f"DJ-unknown-{int(datetime.now().timestamp())}"
    parts = [part for part in urlparse(url).path.split('/') if part]
    return f"DJ-{'-'.join(parts[-4:])}"

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

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    advisory_url = raw_data.get("full_description_url")
                    advisory_id = generate_advisory_id(advisory_url)
                    if not advisory_id: continue

                    # 1. Advisories
                    advisories[advisory_id] = (
                        advisory_id, vendor_id,
                        raw_data.get("description").split('.')[0].strip(), # Use first sentence of desc as title
                        None, # Severity
                        parse_date(raw_data.get("publish_date")),
                        None, # latest_update_date
                        advisory_url
                    )
                    
                    for cve_id in raw_data.get("cve_ids", []):
                        cve_key = (vendor_id, cve_id)
                        
                        # 2. CVEs
                        cves[cve_key] = (
                            vendor_id, cve_id,
                            None, # cwe_id
                            clean_text(raw_data.get("description")),
                            None, None, None, # severity, cvss_score, cvss_vector
                            None, None, # initial/latest release dates
                            advisory_url # Use advisory URL as reference
                        )
                        
                        patch_urls = [v['patch_url'] for v in raw_data.get("affected_versions", []) if v.get('patch_url')]
                        recommendations = "Apply security patches. See details at:\n" + "\n".join(patch_urls) if patch_urls else "See advisory URL for patching details."
                        
                        # 3. Product Map
                        cve_product_maps[cve_key] = (
                            vendor_id, cve_id, None, clean_text(recommendations)
                        )
                        
                        # 4. Map
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")
                
                # --- SQL LOGIC: Living Database + Sequence Sync ---

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) 
                        VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET 
                        title=EXCLUDED.title, 
                        initial_release_date=EXCLUDED.initial_release_date,
                        advisory_url=EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        reference_url=EXCLUDED.reference_url,
                        description=COALESCE(EXCLUDED.description, cves.description);
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
# Django_normal.py (Production Version)
import os
import re
import logging
import psycopg2
from psycopg2.extras import execute_values, Json
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm
from urllib.parse import urlparse

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("django_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Django"

# --- Helper Functions (from your team's script) ---
def clean_text(text):
    if not text: return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

from typing import Optional

def parse_date(date_string: str) -> Optional[datetime.date]:
    if not date_string: return None
    try:
        return datetime.strptime(date_string, "%B %d, %Y").date()
    except (ValueError, TypeError):
        return None

def generate_advisory_id(url: str) -> str:
    if not url: return f"DJ-unknown-{int(datetime.now().timestamp())}"
    parts = [part for part in urlparse(url).path.split('/') if part]
    return f"DJ-{'-'.join(parts[-4:])}"

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

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    advisory_url = raw_data.get("full_description_url")
                    advisory_id = generate_advisory_id(advisory_url)
                    if not advisory_id: continue

                    # Advisory Record - severity is NULL per your rule
                    advisories[advisory_id] = (
                        advisory_id, vendor_id,
                        raw_data.get("description").split('.')[0].strip(), # Use first sentence of desc as title
                        None, # Severity
                        parse_date(raw_data.get("publish_date")),
                        None, # latest_update_date
                        advisory_url
                    )
                    
                    for cve_id in raw_data.get("cve_ids", []):
                        # CVE Record - specified columns are NULL per your rule
                        cves[(vendor_id, cve_id)] = (
                            vendor_id, cve_id,
                            None, # cwe_id
                            clean_text(raw_data.get("description")),
                            None, None, None, # severity, cvss_score, cvss_vector
                            None, None, # initial/latest release dates
                            advisory_url # Use advisory URL as reference
                        )
                        
                        patch_urls = [v['patch_url'] for v in raw_data.get("affected_versions", []) if v.get('patch_url')]
                        recommendations = "Apply security patches. See details at:\n" + "\n".join(patch_urls) if patch_urls else "See advisory URL for patching details."
                        
                        # cve_product_map - affected_products_cpe is NULL per your rule
                        cve_product_maps[(vendor_id, cve_id)] = (
                            vendor_id, cve_id, None, clean_text(recommendations)
                        )
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, initial_release_date=EXCLUDED.initial_release_date;
                    """, list(advisories.values()))
                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET description=EXCLUDED.description;
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
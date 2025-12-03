# Sophos_normal.py (Final Production Version)
import os
import re
import logging
import sys
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("sophos_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Sophos"

# --- Helper Functions ---
def clean_text(text):
    if not text: return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(date_str):
    if not date_str: return None
    for fmt in ("%Y %b %d", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str.strip(), fmt).date()
        except (ValueError, TypeError):
            continue
    return None

def join_or_none(lst):
    if not lst: return None
    cleaned = [str(x).strip() for x in lst if x and str(x).strip()]
    return ", ".join(cleaned) if cleaned else None

def get_recommendations(cve_id, raw_data):
    structured = raw_data.get("structured_remediation", {}) or {}
    fallback = raw_data.get("remediation", []) or []
    if cve_id in structured and (vals := structured.get(cve_id)):
        return " ".join([clean_text(v) for v in vals if clean_text(v)])
    return " ".join([clean_text(v) for v in fallback if clean_text(v)]) or None

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

                advisories, cves, cve_product_maps, advisory_cve_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    meta = raw_data.get("meta", {}) or {}
                    advisory_id = meta.get("publication_id")
                    if not advisory_id: continue

                    # 1. Advisory
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, meta.get("advisory_name"),
                        clean_text(meta.get("impact")),
                        parse_date(meta.get("first_published")),
                        parse_date(meta.get("updated_date")),
                        raw_data.get("advisory_link")
                    )
                    
                    cve_list = meta.get("cves", []) or []
                    reference_url = join_or_none(raw_data.get("related_information"))

                    for cve_id in cve_list:
                        cve_table = raw_data.get("cve_table", []) or []
                        cve_details = next((c for c in cve_table if c.get("cve_id") == cve_id), {})

                        cve_key = (vendor_id, cve_id)
                        
                        # 2. CVE Record
                        cves[cve_key] = (
                            vendor_id, cve_id, None,
                            clean_text(cve_details.get("description")),
                            clean_text(cve_details.get("severity")),
                            None, None, None, None, reference_url
                        )
                        
                        # 3. Product Map
                        cve_product_maps[cve_key] = (
                            vendor_id, cve_id, None, get_recommendations(cve_id, raw_data)
                        )
                        
                        # 4. Map
                        advisory_cve_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk database inserts...")
                
                # --- SQL LOGIC: Living Database + Sequence Sync ---

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) 
                        VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET 
                        title=EXCLUDED.title, 
                        severity=EXCLUDED.severity, 
                        latest_update_date=EXCLUDED.latest_update_date,
                        advisory_url=EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        description=COALESCE(EXCLUDED.description, cves.description), 
                        severity=COALESCE(EXCLUDED.severity, cves.severity), 
                        reference_url=EXCLUDED.reference_url;
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

                if advisory_cve_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) 
                        VALUES %s ON CONFLICT DO NOTHING;
                    """, list(advisory_cve_map))

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
# Sophos_normal.py (Production Version with Text Severity)
import os
import re
import logging
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("sophos_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Sophos"

# --- Helper Functions ---
def clean_text(text):
    if not text: return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(date_str):
    if not date_str: return None
    for fmt in ("%Y %b %d", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str.strip(), fmt).date()
        except (ValueError, TypeError):
            continue
    return None

def join_or_none(lst):
    if not lst: return None
    cleaned = [str(x).strip() for x in lst if x and str(x).strip()]
    return ", ".join(cleaned) if cleaned else None

def get_recommendations(cve_id, raw_data):
    structured = raw_data.get("structured_remediation", {}) or {}
    fallback = raw_data.get("remediation", []) or []
    if cve_id in structured and (vals := structured.get(cve_id)):
        return " ".join([clean_text(v) for v in vals if clean_text(v)])
    return " ".join([clean_text(v) for v in fallback if clean_text(v)]) or None

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

                advisories, cves, cve_product_maps, advisory_cve_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    meta = raw_data.get("meta", {}) or {}
                    advisory_id = meta.get("publication_id")
                    if not advisory_id: continue

                    advisories[advisory_id] = (
                        advisory_id, vendor_id, meta.get("advisory_name"),
                        clean_text(meta.get("impact")),
                        parse_date(meta.get("first_published")),
                        parse_date(meta.get("updated_date")),
                        raw_data.get("advisory_link")
                    )
                    
                    cve_list = meta.get("cves", []) or []
                    reference_url = join_or_none(raw_data.get("related_information"))

                    for cve_id in cve_list:
                        cve_table = raw_data.get("cve_table", []) or []
                        cve_details = next((c for c in cve_table if c.get("cve_id") == cve_id), {})

                        cves[(vendor_id, cve_id)] = (
                            vendor_id, cve_id, None,
                            clean_text(cve_details.get("description")),
                            clean_text(cve_details.get("severity")),
                            None, None, None, None, reference_url
                        )
                        cve_product_maps[(vendor_id, cve_id)] = (
                            vendor_id, cve_id, None, get_recommendations(cve_id, raw_data)
                        )
                        advisory_cve_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, latest_update_date=EXCLUDED.latest_update_date;
                    """, list(advisories.values()))
                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET description=EXCLUDED.description, severity=EXCLUDED.severity, reference_url=EXCLUDED.reference_url;
                    """, list(cves.values()))
                if cve_product_maps:
                    execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations=EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))
                if advisory_cve_map:
                    execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cve_map))

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
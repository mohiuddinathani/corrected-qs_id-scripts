# Opensearch_normal.py (Final Production Version)
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
logger = logging.getLogger("opensearch_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "OpenSearch"

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
                    advisory_id = raw_data.get("GHSA_ID")
                    if not advisory_id: continue
                    
                    cve_details = raw_data.get("CVE_Details", {}) or {}
                    sidebar = cve_details.get("Sidebar_Data", {}) or {}
                    cve_id = sidebar.get("CVE ID")
                    if not cve_id: continue
                    
                    # CWE Logic
                    cwe_id_str = None
                    if cwe_data := cve_details.get("CWE_Data"): # Priority 1
                        cwe_id_str = ",".join([cwe.get("CWE_ID") for cwe in cwe_data if cwe.get("CWE_ID")])
                    elif cwes_list := cve_details.get("CWEs"): # Priority 2
                        cwe_id_str = ",".join(cwes_list)
                    elif weaknesses_str := sidebar.get("Weaknesses"): # Priority 3
                        cwe_id_str = weaknesses_str

                    # 1. Advisory
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("Title"),
                        None, # Advisory severity is NULL
                        parse_date(raw_data.get("Published_Date")),
                        None, # latest_update_date is NULL
                        raw_data.get("Link")
                    )

                    # Reference URL logic
                    refs = cve_details.get("References", {})
                    other_info = cve_details.get("Other_Information", {})
                    ref_links = [r.get("href") for r in refs.get("links", []) if r.get("href")]
                    if not ref_links:
                        ref_links = [r.get("href") for r in other_info.get("links", []) if r.get("href")]
                    reference_url = ", ".join(ref_links) if ref_links else None

                    # Recommendation logic
                    recommendations = cve_details.get("Patched") or cve_details.get("Workarounds")

                    # 2. CVE Record
                    cves[(vendor_id, cve_id)] = (
                        vendor_id, cve_id, 
                        cwe_id_str,
                        clean_text(cve_details.get("Description")) or clean_text(cve_details.get("Impact")),
                        sidebar.get("Severity"), sidebar.get("CVSS Score"), sidebar.get("CVSS Vector"),
                        None, None, # dates
                        reference_url
                    )
                    
                    # 3. Product Map
                    cve_product_maps[(vendor_id, cve_id)] = (
                        vendor_id, cve_id, None, clean_text(recommendations)
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
                        initial_release_date=EXCLUDED.initial_release_date,
                        advisory_url=EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        cwe_id=COALESCE(EXCLUDED.cwe_id, cves.cwe_id), 
                        description=COALESCE(EXCLUDED.description, cves.description), 
                        severity=COALESCE(EXCLUDED.severity, cves.severity), 
                        cvss_score=COALESCE(EXCLUDED.cvss_score, cves.cvss_score), 
                        cvss_vector=COALESCE(EXCLUDED.cvss_vector, cves.cvss_vector),
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
# Opensearch_normal.py (Production Version with Team's Logic)
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
logger = logging.getLogger("opensearch_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "OpenSearch"

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
                    advisory_id = raw_data.get("GHSA_ID")
                    if not advisory_id: continue
                    
                    cve_details = raw_data.get("CVE_Details", {}) or {}
                    sidebar = cve_details.get("Sidebar_Data", {}) or {}
                    cve_id = sidebar.get("CVE ID")
                    if not cve_id: continue
                    

                    cwe_id_str = None
                    if cwe_data := cve_details.get("CWE_Data"): # Priority 1: Detailed data
                        cwe_id_str = ",".join([cwe.get("CWE_ID") for cwe in cwe_data if cwe.get("CWE_ID")])
                    elif cwes_list := cve_details.get("CWEs"): # Priority 2: Simple list of strings
                        cwe_id_str = ",".join(cwes_list)
                    elif weaknesses_str := sidebar.get("Weaknesses"): # Priority 3: Fallback string
                        cwe_id_str = weaknesses_str

                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("Title"),
                        None, # Advisory severity is NULL
                        parse_date(raw_data.get("Published_Date")),
                        None, # latest_update_date is NULL
                        raw_data.get("Link")
                    )

                    # Reference URL logic: References first, fallback to Other_Information
                    refs = cve_details.get("References", {})
                    other_info = cve_details.get("Other_Information", {})
                    ref_links = [r.get("href") for r in refs.get("links", []) if r.get("href")]
                    if not ref_links:
                        ref_links = [r.get("href") for r in other_info.get("links", []) if r.get("href")]
                    reference_url = ", ".join(ref_links) if ref_links else None

                    # Recommendation logic
                    recommendations = cve_details.get("Patched") or cve_details.get("Workarounds")

                    cves[(vendor_id, cve_id)] = (
                        vendor_id, cve_id, 
                        cwe_id_str,
                        clean_text(cve_details.get("Description")) or clean_text(cve_details.get("Impact")),
                        sidebar.get("Severity"), sidebar.get("CVSS Score"), sidebar.get("CVSS Vector"),
                        None, None, # initial/latest release dates are NULL
                        reference_url
                    )
                    
                    cve_product_maps[(vendor_id, cve_id)] = (
                        vendor_id, cve_id, None, clean_text(recommendations)
                    )
                    advisory_cve_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, initial_release_date=EXCLUDED.initial_release_date;
                    """, list(advisories.values()))
                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET cwe_id=EXCLUDED.cwe_id, description=EXCLUDED.description, severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score, cvss_vector=EXCLUDED.cvss_vector;
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
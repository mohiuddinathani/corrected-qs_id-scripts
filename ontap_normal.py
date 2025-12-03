# NetApp_normal.py (Final Production Version)
import os
import re
import logging
import psycopg2
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv
from tqdm import tqdm
from datetime import datetime
import sys

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("okta_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "NetApp"

# --- Helper Functions ---

def extract_cvss(cvss_text):
    """Extract numeric CVSS score and vector string from raw CVSS text."""
    if not cvss_text or not isinstance(cvss_text, str): return None, None
    score_match = re.search(r"Score:\s*([\d.]+)", cvss_text)
    vector_match = re.search(r"Vector string:\s*(.+)", cvss_text)
    score = float(score_match.group(1)) if score_match else None
    vector = vector_match.group(1).strip() if vector_match else None
    return score, vector

def parse_date(date_string):
    """Parses multiple potential date formats from Okta's site."""
    if not date_string: return None
    formats_to_try = [
        "%b %d, %Y",  # e.g., "Sep 27, 2023"
        "%B %d, %Y",  # e.g., "September 27, 2023"
    ]
    for fmt in formats_to_try:
        try:
            return datetime.strptime(date_string.strip(), fmt).date()
        except (ValueError, TypeError):
            continue
    logger.warning(f"Could not parse date: {date_string}")
    return None

def cvss_to_severity(score):
    """Maps a CVSS score to a severity rating."""
    if score is None or not isinstance(score, (int, float)): return None
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    if score < 4.0: return "Low"
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

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    advisory_url = raw_data.get("url")
                    if not advisory_url: continue
                    
                    advisory_id = raw_data.get("title", f"okta-sa-{staging_id}") # Using title as a more stable ID
                    cve_details = raw_data.get("cve_details", {})
                    cve_id = cve_details.get("CVE ID")

                    # --- Advisory Data ---
                    initial_date = parse_date(raw_data.get("initial_date"))
                    
                    # Find latest date from timeline
                    timeline_entries = raw_data.get("timeline", [])
                    latest_date = initial_date
                    if timeline_entries:
                        parsed_dates = [d for d in [parse_date(entry.split(":", 1)[-1]) for entry in timeline_entries] if d]
                        if parsed_dates:
                            latest_date = max(parsed_dates)

                    # Get CVSS score for advisory severity
                    cvss_text_for_sev = cve_details.get("CVSS v3", "")
                    cvss_score_for_sev, _ = extract_cvss(cvss_text_for_sev)

                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("title"),
                        cvss_to_severity(cvss_score_for_sev),
                        initial_date, latest_date, advisory_url
                    )

                    # --- CVE and Mapping Data ---
                    if cve_id:
                        cwe_id = cve_details.get("CWE")
                        description = raw_data.get("description")
                        
                        cvss_text = cve_details.get("CVSS v3", "")
                        cvss_score, cvss_vector = extract_cvss(cvss_text)
                        
                        cve_key = (vendor_id, cve_id)
                        cves[cve_key] = (
                            vendor_id, cve_id, cwe_id, description,
                            cvss_to_severity(cvss_score), cvss_score, cvss_vector,
                            initial_date, latest_date, advisory_url
                        )
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))
                        
                        affected_products = Json(raw_data.get("affected_products", None))
                        recommendations = raw_data.get("resolution")
                        cve_product_maps[cve_key] = (vendor_id, cve_id, affected_products, recommendations)

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
                        cwe_id=EXCLUDED.cwe_id, 
                        description=COALESCE(EXCLUDED.description, cves.description), 
                        severity=COALESCE(EXCLUDED.severity, cves.severity), 
                        cvss_score=COALESCE(EXCLUDED.cvss_score, cves.cvss_score), 
                        cvss_vector=COALESCE(EXCLUDED.cvss_vector, cves.cvss_vector), 
                        latest_update_date=EXCLUDED.latest_update_date, 
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
                        affected_products_cpe=EXCLUDED.affected_products_cpe, 
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
                logger.info(f"✅ Normalization complete for {len(rows)} records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()
'''
# okta_normal.py (Production Version - Corrected)
import os
import re
import logging
import psycopg2
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv
from tqdm import tqdm
from datetime import datetime

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("okta_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "Okta"

# --- Helper Functions ---

# RESTORED: This is your exact CVSS extraction function.
def extract_cvss(cvss_text):
    """Extract numeric CVSS score and vector string from raw CVSS text."""
    if not cvss_text or not isinstance(cvss_text, str): return None, None
    score_match = re.search(r"Score:\s*([\d.]+)", cvss_text)
    vector_match = re.search(r"Vector string:\s*(.+)", cvss_text)
    score = float(score_match.group(1)) if score_match else None
    vector = vector_match.group(1).strip() if vector_match else None
    return score, vector

def parse_date(date_string):
    """Parses multiple potential date formats from Okta's site."""
    if not date_string: return None
    # Prioritizing the format from your original script
    formats_to_try = [
        "%b %d, %Y",  # e.g., "Sep 27, 2023"
        "%B %d, %Y",  # e.g., "September 27, 2023"
    ]
    for fmt in formats_to_try:
        try:
            return datetime.strptime(date_string.strip(), fmt).date()
        except (ValueError, TypeError):
            continue
    logger.warning(f"Could not parse date: {date_string}")
    return None

def cvss_to_severity(score):
    """Maps a CVSS score to a severity rating."""
    if score is None or not isinstance(score, (int, float)): return None
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    if score < 4.0: return "Low"
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

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    advisory_url = raw_data.get("url")
                    if not advisory_url: continue
                    
                    advisory_id = raw_data.get("title", f"okta-sa-{staging_id}") # Using title as a more stable ID
                    cve_details = raw_data.get("cve_details", {})
                    cve_id = cve_details.get("CVE ID")

                    # --- Advisory Data ---
                    # Using 'initial_date' from your raw script's logic
                    initial_date = parse_date(raw_data.get("initial_date"))
                    
                    # More robustly find latest date from timeline
                    timeline_entries = raw_data.get("timeline", [])
                    latest_date = initial_date
                    if timeline_entries:
                        parsed_dates = [d for d in [parse_date(entry.split(":", 1)[-1]) for entry in timeline_entries] if d]
                        if parsed_dates:
                            latest_date = max(parsed_dates)

                    # RESTORED: Use your logic to get CVSS score for advisory severity
                    cvss_text_for_sev = cve_details.get("CVSS v3", "")
                    cvss_score_for_sev, _ = extract_cvss(cvss_text_for_sev)

                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("title"),
                        cvss_to_severity(cvss_score_for_sev),
                        initial_date, latest_date, advisory_url
                    )

                    # --- CVE and Mapping Data ---
                    if cve_id:
                        cwe_id = cve_details.get("CWE")
                        description = raw_data.get("description")
                        
                        # RESTORED: Get CVSS text from "CVSS v3" key and parse with your function
                        cvss_text = cve_details.get("CVSS v3", "")
                        cvss_score, cvss_vector = extract_cvss(cvss_text)
                        
                        cves[(vendor_id, cve_id)] = (
                            vendor_id, cve_id, cwe_id, description,
                            cvss_to_severity(cvss_score), cvss_score, cvss_vector,
                            initial_date, latest_date, advisory_url
                        )
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))
                        
                        affected_products = Json(raw_data.get("affected_products", None))
                        # RESTORED: Get recommendations from the "resolution" key as per your original script
                        recommendations = raw_data.get("resolution")
                        cve_product_maps[(vendor_id, cve_id)] = (vendor_id, cve_id, affected_products, recommendations)

                logger.info("Performing bulk database inserts...")
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, latest_update_date=EXCLUDED.latest_update_date, advisory_url=EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET cwe_id=EXCLUDED.cwe_id, description=EXCLUDED.description, severity=EXCLUDED.severity, cvss_score=EXcluded.cvss_score, cvss_vector=EXCLUDED.cvss_vector, latest_update_date=EXCLUDED.latest_update_date, reference_url=EXCLUDED.reference_url;
                    """, list(cves.values()))

                if cve_product_maps:
                    execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET affected_products_cpe=EXCLUDED.affected_products_cpe, recommendations=EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))

                if advisory_cves_map:
                    execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cves_map))

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


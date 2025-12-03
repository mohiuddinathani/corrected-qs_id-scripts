# oracle_normal.py (Final Hardened Version)
import logging, re, os, sys
from collections import Counter
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import execute_values, Json
from tqdm import tqdm
from datetime import datetime

# --- Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
}
VENDOR_NAME = "Oracle"

# --- Helper Functions ---
def get_severity_from_score(score):
    if not score or score == 'N/A': return None
    try:
        s = float(score)
        if 0.1 <= s <= 3.9: return "Low"
        if 4.0 <= s <= 6.9: return "Medium"
        if 7.0 <= s <= 8.9: return "High"
        if 9.0 <= s <= 10.0: return "Critical"
    except (ValueError, TypeError): return None
    return None

def safe_numeric(score_str):
    """Safely converts a string to a float, handling typos like '0.0.'"""
    if not score_str or score_str == 'N/A': return None
    try:
        cleaned_str = str(score_str).strip().rstrip('.')
        return float(cleaned_str)
    except (ValueError, TypeError):
        return None

def parse_verbose_block(text_block):
    """Robustly extracts details from the verbose text block."""
    details = {'description': 'Details not found.', 'cvss_score': 'N/A', 'cvss_vector': 'N/A'}
    if not text_block: return details

    score_match = re.search(r"CVSS\s+v?3\.\d\s+Base\s+Score\s+([\d\.]+)", text_block, re.IGNORECASE)
    vector_match = re.search(r"CVSS\s+Vector:\s*\((CVSS:3\.\d/[^\)]+)\)", text_block, re.IGNORECASE)
    if score_match: details['cvss_score'] = score_match.group(1)
    if vector_match: details['cvss_vector'] = vector_match.group(1)

    desc_parts = re.split(r'CVSS\s+v?\d\.\d?\s+Base\s+Score', text_block, flags=re.IGNORECASE)
    if desc_parts[0]:
        description_text = re.sub(r'^CVE-\d{4}-\d{4,7}', '', desc_parts[0], count=1).strip()
        details['description'] = description_text

    return details

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
                cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE processed = FALSE AND vendor_name = %s;", (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info("No new Oracle records to process.")
                    return

                advisories, cves, cve_product_maps = {}, {}, {}
                advisory_cve_map = set()
                
                for staging_id, raw_entry in tqdm(rows, desc="Parsing Staged Data"):
                    advisory_url = raw_entry.get('advisory_url', '')
                    original_id = advisory_url.split('/')[-1].replace('.html', '')
                    advisory_id = f"ORACLE-{original_id.upper()}"
                    
                    verbose_details = parse_verbose_block(raw_entry.get('verbose_text_block', ''))
                    
                    cvss_score = safe_numeric(verbose_details['cvss_score'])
                    severity = get_severity_from_score(cvss_score)
                    cve_id = raw_entry.get('cve_id')
                    if not cve_id: continue

                    # 1. Advisory
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_entry.get('title'),
                        severity, None, None, advisory_url
                    )

                    cve_key = (vendor_id, cve_id)

                    # 2. CVE Record
                    cves[cve_key] = (
                        vendor_id, cve_id, None, verbose_details['description'], severity,
                        cvss_score, verbose_details['cvss_vector'],
                        None, None, advisory_url
                    )
                    
                    # 3. Product Map
                    cve_product_maps[cve_key] = (vendor_id, cve_id, None, "Apply patches as per the advisory.")
                    
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
                        severity=EXCLUDED.severity;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        description=COALESCE(EXCLUDED.description, cves.description), 
                        severity=COALESCE(EXCLUDED.severity, cves.severity), 
                        cvss_score=COALESCE(EXCLUDED.cvss_score, cves.cvss_score), 
                        cvss_vector=COALESCE(EXCLUDED.cvss_vector, cves.cvss_vector);
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
# oracle_normal.py (Final Hardened Version)
import logging, re, os, sys
from collections import Counter
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import execute_values, Json
from tqdm import tqdm
from datetime import datetime

# --- Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
}
VENDOR_NAME = "Oracle"

# --- Helper Functions ---
def get_severity_from_score(score):
    if not score or score == 'N/A': return None
    try:
        s = float(score)
        if 0.1 <= s <= 3.9: return "Low"
        if 4.0 <= s <= 6.9: return "Medium"
        if 7.0 <= s <= 8.9: return "High"
        if 9.0 <= s <= 10.0: return "Critical"
    except (ValueError, TypeError): return None
    return None

def safe_numeric(score_str):
    """Safely converts a string to a float, handling typos like '0.0.'"""
    if not score_str or score_str == 'N/A': return None
    try:
        # Clean up common typos before converting
        cleaned_str = score_str.strip().rstrip('.')
        return float(cleaned_str)
    except (ValueError, TypeError):
        return None

def parse_verbose_block(text_block):
    """Robustly extracts details from the verbose text block."""
    details = {'description': 'Details not found.', 'cvss_score': 'N/A', 'cvss_vector': 'N/A'}
    if not text_block: return details

    score_match = re.search(r"CVSS\s+v?3\.\d\s+Base\s+Score\s+([\d\.]+)", text_block, re.IGNORECASE)
    vector_match = re.search(r"CVSS\s+Vector:\s*\((CVSS:3\.\d/[^\)]+)\)", text_block, re.IGNORECASE)
    if score_match: details['cvss_score'] = score_match.group(1)
    if vector_match: details['cvss_vector'] = vector_match.group(1)

    desc_parts = re.split(r'CVSS\s+v?\d\.\d?\s+Base\s+Score', text_block, flags=re.IGNORECASE)
    if desc_parts[0]:
        description_text = re.sub(r'^CVE-\d{4}-\d{4,7}', '', desc_parts[0], count=1).strip()
        details['description'] = description_text

    return details

def main():
    logger.info(f"🚀 Starting Final {VENDOR_NAME} Processor (Pass 1)...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE processed = FALSE AND vendor_name = %s;", (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info("No new Oracle records to process.")
                    return

                advisories, cves, cve_product_maps = {}, {}, {}
                advisory_cve_map = set()
                
                for staging_id, raw_entry in tqdm(rows, desc="Parsing Staged Data"):
                    advisory_url = raw_entry.get('advisory_url', '')
                    original_id = advisory_url.split('/')[-1].replace('.html', '')
                    advisory_id = f"ORACLE-{original_id.upper()}"
                    
                    verbose_details = parse_verbose_block(raw_entry.get('verbose_text_block', ''))
                    
                    # --- THIS IS THE FIX: Use the safe_numeric helper ---
                    cvss_score = safe_numeric(verbose_details['cvss_score'])
                    severity = get_severity_from_score(cvss_score)
                    cve_id = raw_entry.get('cve_id')
                    if not cve_id: continue

                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_entry.get('title'),
                        severity, None, None, advisory_url
                    )
                    cves[cve_id] = (
                        vendor_id, cve_id, None, verbose_details['description'], severity,
                        cvss_score, verbose_details['cvss_vector'],
                        None, None, advisory_url
                    )
                    advisory_cve_map.add((advisory_id, vendor_id, cve_id))
                    cve_product_maps[cve_id] = (vendor_id, cve_id, None, "Apply patches as per the advisory.")

                logger.info("Performing bulk inserts...")
                if advisories: execute_values(cur, "INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity;", list(advisories.values()))
                if cves: execute_values(cur, "INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET description=COALESCE(EXCLUDED.description,cves.description), severity=COALESCE(EXCLUDED.severity,cves.severity), cvss_score=COALESCE(EXCLUDED.cvss_score,cves.cvss_score), cvss_vector=COALESCE(EXCLUDED.cvss_vector,cves.cvss_vector);", list(cves.values()))
                if advisory_cve_map: execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id,vendor_id,  cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cve_map))
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
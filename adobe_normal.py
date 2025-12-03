# adobe_final_normalizer.py (Corrected Version)
import re, json, psycopg2, os
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
import logging, sys
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
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
VENDOR_NAME = "Adobe"

# --- Helper Functions (Unchanged) ---

def extract_cwe(text):
    """Extracts and standardizes a CWE identifier from a string, ignoring case."""
    match = re.search(r"CWE-\d+", str(text), re.IGNORECASE)
    if not match:
        return None
    return match.group(0).upper()

def extract_cves(text):
    """Extracts all CVE identifiers from a string."""
    return re.findall(r"CVE-\d{4}-\d{4,7}", str(text))

def extract_cvss(text):
    """Extracts a CVSS score from a string."""
    match = re.search(r"\b\d{1,2}\.\d{1,2}\b", str(text))
    return match.group(0) if match else None

def safe_date(date_str):
    """Parses MM/DD/YYYY to a date object, returning None on failure."""
    if not date_str or date_str == "Not Available":
        return None
    try:
        return datetime.strptime(date_str, '%m/%d/%Y').date()
    except (ValueError, TypeError):
        return None

def safe_numeric(num_str):
    """Converts a string to a float, returning None on failure."""
    if num_str is None or num_str == "Not Available":
        return None
    try:
        return float(num_str)
    except (ValueError, TypeError):
        return None

# --- Main Processing Logic ---

def normalize_and_load():
    """Main function to fetch, normalize, and load Adobe security advisory data."""
    
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                logger.info(f"🚀 Starting {VENDOR_NAME} Processor...")
                
                cur.execute(
                    "SELECT staging_id, raw_data FROM vendor_staging_table WHERE processed = false AND vendor_name = %s;",
                    (VENDOR_NAME,)
                )
                staged_records = cur.fetchall()

                if not staged_records:
                    logger.info("✅ No new records to process.")
                    return

                logger.info(f"Found {len(staged_records)} new records to process.")
                
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]
                
                # *** FIX: Use dictionaries to automatically handle duplicates ***
                advisories = {}
                cves = {}
                advisory_cves_map = set() # A set is fine for this simple mapping

                for staging_id, raw_data in tqdm(staged_records, desc="Normalizing Data"):
                    advisory_id = raw_data.get("advisory_id")
                    if not advisory_id:
                        continue

                    advisory_severity = None
                    vuln_table = raw_data.get("vulnerability_table", [])

                    if vuln_table and len(vuln_table) > 1:
                        headers = [h.strip().lower() for h in vuln_table[0]]
                        for r in vuln_table[1:]:
                            row_data = dict(zip(headers, r))
                            cve_cell = row_data.get('cve', row_data.get('cve number', row_data.get('cve numbers', '')))
                            cve_list = extract_cves(cve_cell)

                            if not cve_list:
                                continue
                            
                            cwe_cell = row_data.get('vulnerability category', row_data.get('cwe', ''))
                            severity = row_data.get('severity')
                            if severity and not advisory_severity:
                                advisory_severity = severity
                            
                            for cve_id in cve_list:
                                # Use a tuple as the key for the cves dictionary
                                cve_key = (vendor_id, cve_id)
                                cves[cve_key] = (
                                    vendor_id, cve_id, extract_cwe(cwe_cell),
                                    raw_data.get("description"), severity,
                                    safe_numeric(extract_cvss(row_data.get('cvss base score', ''))),
                                    row_data.get('cvss vector'),
                                    None,
                                    None,
                                    raw_data.get("advisory_url")
                                )
                                advisory_cves_map.add((advisory_id, vendor_id, cve_id))
                    
                    # By using the advisory_id as the key, any duplicates are automatically overwritten
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("title"), advisory_severity,
                        safe_date(raw_data.get("initial_release_date")),
                        safe_date(raw_data.get("latest_updated_date")),
                        raw_data.get("advisory_url")
                    )
                
                logger.info("Performing bulk inserts into production tables...")

                # *** FIX: Insert the .values() from the dictionaries ***
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                        VALUES %s ON CONFLICT (advisory_id) DO UPDATE SET
                        title = EXCLUDED.title, severity = EXCLUDED.severity, latest_update_date = EXCLUDED.latest_update_date;
                    """, list(advisories.values()))
                
                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
                        VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET
                        cwe_id = EXCLUDED.cwe_id, description = EXCLUDED.description, severity = EXCLUDED.severity, cvss_score = EXCLUDED.cvss_score, latest_update_date = EXCLUDED.latest_update_date;
                    """, list(cves.values()))

                if advisory_cves_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id)
                        VALUES %s ON CONFLICT DO NOTHING;
                    """, list(advisory_cves_map))
                
                processed_ids = tuple(rec[0] for rec in staged_records)
                cur.execute("UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Successfully processed and loaded {len(staged_records)} records.")

    except psycopg2.Error as e:
        logger.error(f"❌ Database error occurred: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"❌ An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    normalize_and_load()






'''
# adobe_final_normalizer.py (Corrected Version)
import re, json, psycopg2, os
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
import logging, sys
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
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
VENDOR_NAME = "Adobe"

# --- Helper Functions (Unchanged) ---

def extract_cwe(text):
    """Extracts and standardizes a CWE identifier from a string, ignoring case."""
    match = re.search(r"CWE-\d+", str(text), re.IGNORECASE)
    if not match:
        return None
    return match.group(0).upper()

def extract_cves(text):
    """Extracts all CVE identifiers from a string."""
    return re.findall(r"CVE-\d{4}-\d{4,7}", str(text))

def extract_cvss(text):
    """Extracts a CVSS score from a string."""
    match = re.search(r"\b\d{1,2}\.\d{1,2}\b", str(text))
    return match.group(0) if match else None

def safe_date(date_str):
    """Parses MM/DD/YYYY to a date object, returning None on failure."""
    if not date_str or date_str == "Not Available":
        return None
    try:
        return datetime.strptime(date_str, '%m/%d/%Y').date()
    except (ValueError, TypeError):
        return None

def safe_numeric(num_str):
    """Converts a string to a float, returning None on failure."""
    if num_str is None or num_str == "Not Available":
        return None
    try:
        return float(num_str)
    except (ValueError, TypeError):
        return None

# --- Main Processing Logic ---

def normalize_and_load():
    """Main function to fetch, normalize, and load Adobe security advisory data."""
    
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                logger.info(f"🚀 Starting {VENDOR_NAME} Processor...")
                
                cur.execute(
                    "SELECT staging_id, raw_data FROM vendor_staging_table WHERE processed = false AND vendor_name = %s;",
                    (VENDOR_NAME,)
                )
                staged_records = cur.fetchall()

                if not staged_records:
                    logger.info("✅ No new records to process.")
                    return

                logger.info(f"Found {len(staged_records)} new records to process.")
                
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]
                
                # *** FIX: Use dictionaries to automatically handle duplicates ***
                advisories = {}
                cves = {}
                advisory_cves_map = set() # A set is fine for this simple mapping

                for staging_id, raw_data in tqdm(staged_records, desc="Normalizing Data"):
                    advisory_id = raw_data.get("advisory_id")
                    if not advisory_id:
                        continue

                    advisory_severity = None
                    vuln_table = raw_data.get("vulnerability_table", [])

                    if vuln_table and len(vuln_table) > 1:
                        headers = [h.strip().lower() for h in vuln_table[0]]
                        for r in vuln_table[1:]:
                            row_data = dict(zip(headers, r))
                            cve_cell = row_data.get('cve', row_data.get('cve number', row_data.get('cve numbers', '')))
                            cve_list = extract_cves(cve_cell)

                            if not cve_list:
                                continue
                            
                            cwe_cell = row_data.get('vulnerability category', row_data.get('cwe', ''))
                            severity = row_data.get('severity')
                            if severity and not advisory_severity:
                                advisory_severity = severity
                            
                            for cve_id in cve_list:
                                # Use a tuple as the key for the cves dictionary
                                cve_key = (vendor_id, cve_id)
                                cves[cve_key] = (
                                    vendor_id, cve_id, extract_cwe(cwe_cell),
                                    raw_data.get("description"), severity,
                                    safe_numeric(extract_cvss(row_data.get('cvss base score', ''))),
                                    row_data.get('cvss vector'),
                                    None,
                                    None,
                                    raw_data.get("advisory_url")
                                )
                                advisory_cves_map.add((advisory_id, vendor_id, cve_id))
                    
                    # By using the advisory_id as the key, any duplicates are automatically overwritten
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("title"), advisory_severity,
                        safe_date(raw_data.get("initial_release_date")),
                        safe_date(raw_data.get("latest_updated_date")),
                        raw_data.get("advisory_url")
                    )
                
                logger.info("Performing bulk inserts into production tables...")

                # *** FIX: Insert the .values() from the dictionaries ***
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                        VALUES %s ON CONFLICT (advisory_id) DO UPDATE SET
                        title = EXCLUDED.title, severity = EXCLUDED.severity, latest_update_date = EXCLUDED.latest_update_date;
                    """, list(advisories.values()))
                
                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
                        VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET
                        cwe_id = EXCLUDED.cwe_id, description = EXCLUDED.description, severity = EXCLUDED.severity, cvss_score = EXCLUDED.cvss_score, latest_update_date = EXCLUDED.latest_update_date;
                    """, list(cves.values()))

                if advisory_cves_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id)
                        VALUES %s ON CONFLICT DO NOTHING;
                    """, list(advisory_cves_map))
                
                processed_ids = tuple(rec[0] for rec in staged_records)
                cur.execute("UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Successfully processed and loaded {len(staged_records)} records.")

    except psycopg2.Error as e:
        logger.error(f"❌ Database error occurred: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"❌ An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    normalize_and_load()
'''
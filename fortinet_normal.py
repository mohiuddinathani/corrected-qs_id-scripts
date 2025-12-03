# Fortinet_normal.py (Final Production Version)
import os
import psycopg2
import psycopg2.extras
from datetime import datetime
from dotenv import load_dotenv
import logging, sys
from tqdm import tqdm
import re

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("fortinet_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Fortinet Networks"

# --- Helper Functions ---
def parse_date(date_str):
    if not date_str or date_str.strip() == "": return None
    try: return datetime.strptime(date_str, "%b %d, %Y").date()
    except (ValueError, TypeError): return None

def safe_numeric(val):
    try: return round(float(val), 1) if val else None
    except (ValueError, TypeError): return None

def extract_cwe(description):
    """Extracts a CWE ID from a string using a more robust regex."""
    if not description:
        return None
    # This pattern ignores case (CWE vs cwe) and allows spaces around the hyphen
    match = re.search(r'CWE\s*-\s*\d+', description, re.IGNORECASE)
    return match.group(0).upper() if match else None  

def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                # Ensure Vendor Exists
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                # Fetch Staged Data
                cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE processed = FALSE AND vendor_name = %s;", (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info("No new Fortinet records to process.")
                    return

                advisories, cves, cve_product_maps = {}, {}, {}
                advisory_cve_map = set()

                for staging_id, raw in tqdm(rows, desc="Parsing Staged Data"):
                    advisory_id = raw.get("ir_number")
                    if not advisory_id:
                        continue

                    # 1. Advisories
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw.get("description"), # Using description as title if title unavailable
                        raw.get("severity"), parse_date(raw.get("published_date")),
                        parse_date(raw.get("updated_date")), raw.get("url")
                    )

                    for cve_id in raw.get("cve_id_list", []):
                        if not cve_id: continue
                        
                        cve_key = (vendor_id, cve_id)
                        cwe_id = extract_cwe(raw.get("description"))

                        # 2. CVEs
                        cves[cve_key] = (
                            vendor_id, cve_id, cwe_id, 
                            raw.get("description"),
                            raw.get("severity"), 
                            safe_numeric(raw.get("cvssv3_score")),
                            None, None, None, # vector, dates
                            raw.get("url")
                        )
                        
                        # 3. Product Map
                        cve_product_maps[cve_key] = (
                            vendor_id, cve_id, 
                            None, # affected_products_cpe
                            raw.get("solution")
                        )
                        
                        # 4. Map
                        advisory_cve_map.add((advisory_id, vendor_id, cve_id))

                logger.info(f"Performing bulk inserts for {len(advisories)} unique advisories...")
                
                # --- SQL LOGIC: Living Database + Sequence Sync ---

                if advisories:
                    psycopg2.extras.execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                        VALUES %s ON CONFLICT (advisory_id) DO UPDATE SET
                        title = EXCLUDED.title, 
                        severity = EXCLUDED.severity, 
                        latest_update_date = EXCLUDED.latest_update_date,
                        advisory_url = EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    psycopg2.extras.execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
                        VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET
                        description = COALESCE(EXCLUDED.description, cves.description), 
                        severity = COALESCE(EXCLUDED.severity, cves.severity),
                        cvss_score = COALESCE(EXCLUDED.cvss_score, cves.cvss_score),
                        cwe_id = COALESCE(EXCLUDED.cwe_id, cves.cwe_id),
                        latest_update_date = EXCLUDED.latest_update_date;
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
                    psycopg2.extras.execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations)
                        VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        recommendations = EXCLUDED.recommendations,
                        affected_products_cpe = EXCLUDED.affected_products_cpe;
                    """, list(cve_product_maps.values()))

                if advisory_cve_map:
                    psycopg2.extras.execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) 
                        VALUES %s ON CONFLICT DO NOTHING;
                    """, list(advisory_cve_map))

                # Mark processed + Timestamp
                processed_ids = tuple(row[0] for row in rows)
                if processed_ids:
                    cur.execute("UPDATE vendor_staging_table SET processed = TRUE, processed_at = NOW() WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} staged records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()

'''
# Fortinet_normal.py (Final Production Version)
import os
import psycopg2
import psycopg2.extras
from datetime import datetime
from dotenv import load_dotenv
import logging, sys
from tqdm import tqdm
import re

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Fortinet Networks"

# --- Helper Functions ---
def parse_date(date_str):
    if not date_str or date_str.strip() == "": return None
    try: return datetime.strptime(date_str, "%b %d, %Y").date()
    except (ValueError, TypeError): return None

def safe_numeric(val):
    try: return round(float(val), 1) if val else None
    except (ValueError, TypeError): return None

def extract_cwe(description):
    """Extracts a CWE ID from a string using a more robust regex."""
    if not description:
        return None
    # This pattern ignores case (CWE vs cwe) and allows spaces around the hyphen
    match = re.search(r'CWE\s*-\s*\d+', description, re.IGNORECASE)
    return match.group(0) if match else None  

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
                    logger.info("No new Fortinet records to process.")
                    return

                advisories, cves, cve_product_maps = {}, {}, {}
                advisory_cve_map = set()

                for staging_id, raw in tqdm(rows, desc="Parsing Staged Data"):
                    advisory_id = raw.get("ir_number")
                    if not advisory_id:
                        continue

                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw.get("description"),
                        raw.get("severity"), parse_date(raw.get("published_date")),
                        parse_date(raw.get("updated_date")), raw.get("url")
                    )

                    # ✅ FIX: properly nested inside
                    for cve_id in raw.get("cve_id_list", []):
                        cwe_id = extract_cwe(raw.get("description"))

                        cves[cve_id] = (
                            vendor_id, cve_id, cwe_id, raw.get("description"),
                            raw.get("severity"), safe_numeric(raw.get("cvssv3_score")),
            None, None, None, raw.get("url")
                        )
                        advisory_cve_map.add((advisory_id, vendor_id, cve_id))
                        cve_product_maps[cve_id] = (vendor_id, cve_id, None, raw.get("solution"))
                

                logger.info(f"Performing bulk inserts for {len(advisories)} unique advisories...")
                if advisories:
                    psycopg2.extras.execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                        VALUES %s ON CONFLICT (advisory_id) DO UPDATE SET
                        title = EXCLUDED.title, severity = EXCLUDED.severity, latest_update_date = EXCLUDED.latest_update_date;
                    """, list(advisories.values()))
                if cves:
                    psycopg2.extras.execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
                        VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET
                        description = COALESCE(EXCLUDED.description, cves.description), severity = COALESCE(EXCLUDED.severity, cves.severity),
                        cvss_score = COALESCE(EXCLUDED.cvss_score, cves.cvss_score), latest_update_date = EXCLUDED.latest_update_date;
                    """, list(cves.values()))
                if advisory_cve_map:
                    psycopg2.extras.execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id,vendor_id,  cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cve_map))
                if cve_product_maps:
                    psycopg2.extras.execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations)
                        VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations = EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))

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
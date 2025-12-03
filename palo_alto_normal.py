# palo_alto_normal.py (Final Production Version)
import os
import logging
import json
import sys
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from tqdm import tqdm
from datetime import datetime

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("paloalto_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "Palo Alto Networks"

# --- HELPER FUNCTIONS ---
def parse_date(date_string):
    if not date_string: return None
    try: return datetime.fromisoformat(date_string).date()
    except (ValueError, TypeError): return None

def extract_value(data_field):
    if isinstance(data_field, list) and data_field:
        return data_field[0].get('value')
    elif isinstance(data_field, dict):
        return data_field.get('value')
    return None

def normalize_cvss_vector(adv_data):
    version = adv_data.get("cvss_version", "3.1")
    CVSS_MAP = {
        "AV": {"NETWORK": "N", "LOCAL": "L", "ADJACENT_NETWORK": "A", "PHYSICAL": "P"},
        "AC": {"LOW": "L", "HIGH": "H"}, "PR": {"NONE": "N", "LOW": "L", "HIGH": "H"},
        "UI": {"NONE": "N", "REQUIRED": "R"}, "S": {"UNCHANGED": "U", "CHANGED": "C"},
        "C": {"NONE": "N", "LOW": "L", "HIGH": "H"}, "I": {"NONE": "N", "LOW": "L", "HIGH": "H"},
        "A": {"NONE": "N", "LOW": "L", "HIGH": "H"}
    }
    parts = [f"{m}:{CVSS_MAP.get(m, {}).get(adv_data.get(m, '').upper(), 'X')}" for m in ["AV","AC","PR","UI","S","C","I","A"]]
    return f"CVSS:{version}/" + "/".join(parts)

def generate_pan_id(updated_date_str, staging_id):
    try:
        dt = datetime.fromisoformat(updated_date_str)
    except (ValueError, TypeError, AttributeError):
        dt = datetime.now()
    return f"PAN-SA-{dt.strftime('%Y%m')}-{int(staging_id):04d}"


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
                    logger.info("No new Palo Alto Networks records to process.")
                    return

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()
                
                for staging_id, raw_data in tqdm(rows, desc="Parsing Palo Alto Data"):
                    # Parse JSON string safely
                    if isinstance(raw_data, str):
                        try:
                            raw_data = json.loads(raw_data)
                        except Exception as e:
                            logger.warning(f"Invalid JSON for staging_id={staging_id}: {e}")
                            continue
                        
                    advisory_id = raw_data.get('ID') or generate_pan_id(raw_data.get('updated', ''), staging_id)
                    
                    # Get vendor CVE if available
                    possible_cve = raw_data.get('CVE') or raw_data.get('relatedCVE') or raw_data.get('ID')
                    if isinstance(possible_cve, list):
                        possible_cve = possible_cve[0] if possible_cve else None
                    if isinstance(possible_cve, dict):
                        possible_cve = possible_cve.get('value')

                    cve_id = possible_cve or advisory_id

                    # 1. Advisory
                    advisories[advisory_id] = (
                        advisory_id, vendor_id,
                        raw_data.get('title'), raw_data.get('severity'),
                        parse_date(raw_data.get('date')), parse_date(raw_data.get('updated')),
                        f"https://security.paloaltonetworks.com/{advisory_id}"
                    )

                    # 2. CVE Record
                    if cve_id:
                        cve_key = (vendor_id, cve_id)
                        cves[cve_key] = (
                            vendor_id, cve_id, None,  # cwe_id
                            extract_value(raw_data.get('problem')),
                            raw_data.get('severity'),
                            raw_data.get('baseScore'),
                            normalize_cvss_vector(raw_data),
                            parse_date(raw_data.get('date')),
                            parse_date(raw_data.get('updated')),
                            f"https://security.paloaltonetworks.com/{cve_id}"
                        )
                        
                        # 3. Product Map
                        cve_product_maps[cve_key] = (
                            vendor_id, cve_id, None, extract_value(raw_data.get('solution'))
                        )
                        
                        # 4. Map
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info(f"Total CVEs prepared for insert: {len(cves)}")

                logger.info("Performing bulk inserts...")
                
                # --- SQL LOGIC: Living Database + Sequence Sync ---

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) 
                        VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET 
                        title=EXCLUDED.title, 
                        severity=EXCLUDED.severity, 
                        latest_update_date=EXCLUDED.latest_update_date;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        description=COALESCE(EXCLUDED.description, cves.description), 
                        severity=COALESCE(EXCLUDED.severity, cves.severity), 
                        cvss_score=COALESCE(EXCLUDED.cvss_score, cves.cvss_score), 
                        cvss_vector=COALESCE(EXCLUDED.cvss_vector, cves.cvss_vector), 
                        latest_update_date=EXCLUDED.latest_update_date;
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
                logger.info(f"✅ Normalization complete for {len(rows)} records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()

'''
# palo_alto_normal.py (Production Version)
import os
import logging
import json
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from tqdm import tqdm
from datetime import datetime

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("paloalto_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "Palo Alto Networks"

# --- HELPER FUNCTIONS (from your team's script) ---
def parse_date(date_string):
    if not date_string: return None
    try: return datetime.fromisoformat(date_string).date()
    except (ValueError, TypeError): return None

def extract_value(data_field):
    if isinstance(data_field, list) and data_field:
        return data_field[0].get('value')
    elif isinstance(data_field, dict):
        return data_field.get('value')
    return None

def normalize_cvss_vector(adv_data):
    version = adv_data.get("cvss_version", "3.1")
    CVSS_MAP = {
        "AV": {"NETWORK": "N", "LOCAL": "L", "ADJACENT_NETWORK": "A", "PHYSICAL": "P"},
        "AC": {"LOW": "L", "HIGH": "H"}, "PR": {"NONE": "N", "LOW": "L", "HIGH": "H"},
        "UI": {"NONE": "N", "REQUIRED": "R"}, "S": {"UNCHANGED": "U", "CHANGED": "C"},
        "C": {"NONE": "N", "LOW": "L", "HIGH": "H"}, "I": {"NONE": "N", "LOW": "L", "HIGH": "H"},
        "A": {"NONE": "N", "LOW": "L", "HIGH": "H"}
    }
    parts = [f"{m}:{CVSS_MAP.get(m, {}).get(adv_data.get(m, '').upper(), 'X')}" for m in ["AV","AC","PR","UI","S","C","I","A"]]
    return f"CVSS:{version}/" + "/".join(parts)

def generate_pan_id(updated_date_str, staging_id):
    try:
        dt = datetime.fromisoformat(updated_date_str)
    except (ValueError, TypeError, AttributeError):
        dt = datetime.now()
    return f"PAN-SA-{dt.strftime('%Y%m')}-{int(staging_id):04d}"


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
                    logger.info("No new Palo Alto Networks records to process.")
                    return

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()
                
                
                for staging_id, raw_data in tqdm(rows, desc="Parsing Palo Alto Data"):
                    # Parse JSON string safely
                    if isinstance(raw_data, str):
                        try:
                            raw_data = json.loads(raw_data)
                        except Exception as e:
                            logger.warning(f"Invalid JSON for staging_id={staging_id}: {e}")
                            continue
                        
                    advisory_id = raw_data.get('ID') or generate_pan_id(raw_data.get('updated', ''), staging_id)
                    logger.info(f"✅ Using advisory_id={advisory_id}")

                
                    
                    # Get vendor CVE if available
                    possible_cve = raw_data.get('CVE') or raw_data.get('relatedCVE') or raw_data.get('ID')
                    if isinstance(possible_cve, list):
                        possible_cve = possible_cve[0] if possible_cve else None
                    if isinstance(possible_cve, dict):
                        possible_cve = possible_cve.get('value')

                    cve_id = possible_cve or advisory_id

                    # ✅ Always add advisory (PAN or CVE)
                    advisories[advisory_id] = (
                        advisory_id, vendor_id,
                        raw_data.get('title'), raw_data.get('severity'),
                        parse_date(raw_data.get('date')), parse_date(raw_data.get('updated')),
                        f"https://security.paloaltonetworks.com/{advisory_id}"
                    )

                    # ✅ If CVE found, create CVE record and map to advisory
                    if cve_id:
                        cves[(vendor_id, cve_id)] = (
                            vendor_id, cve_id, None,  # cwe_id
                            extract_value(raw_data.get('problem')),
                            raw_data.get('severity'),
                            raw_data.get('baseScore'),
                            normalize_cvss_vector(raw_data),
                            parse_date(raw_data.get('date')),
                            parse_date(raw_data.get('updated')),
                            f"https://security.paloaltonetworks.com/{cve_id}"
                        )
                        cve_product_maps[(vendor_id, cve_id)] = (
                            vendor_id, cve_id, None, extract_value(raw_data.get('solution'))
                        )
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info(f"Total CVEs prepared for insert: {len(cves)}")

                logger.info("Performing bulk inserts...")
                if advisories: execute_values(cur, "INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, latest_update_date=EXCLUDED.latest_update_date;", list(advisories.values()))
                if cves: execute_values(cur, "INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET description=EXCLUDED.description, severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score, cvss_vector=EXCLUDED.cvss_vector, latest_update_date=EXCLUDED.latest_update_date;", list(cves.values()))
                if cve_product_maps: execute_values(cur, "INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations=EXCLUDED.recommendations;", list(cve_product_maps.values()))
                if advisory_cves_map: execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cves_map))

                processed_ids = tuple(row[0] for row in rows)
                if processed_ids: cur.execute("UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()
    '''
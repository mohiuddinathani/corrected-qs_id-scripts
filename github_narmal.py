# github_normal.py (Final Production Version)
import os
import logging
import psycopg2
import sys
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from tqdm import tqdm
from datetime import datetime

# --- Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("github_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "GitHub"

# --- Helper Functions ---
def parse_date(date_string):
    if not date_string: return None
    try: return datetime.fromisoformat(date_string.replace('Z', '+00:00')).date()
    except (ValueError, TypeError): return None

def build_recommendations(vulnerabilities):
    if not vulnerabilities: return "No specific package information provided."
    reco_lines = ["Affected packages:"]
    for edge in vulnerabilities.get('edges', []):
        node = edge.get('node', {})
        pkg_name = (node.get('package', {}) or {}).get('name')
        patched_version = (node.get('firstPatchedVersion', {}) or {}).get('identifier')
        line = f"- {pkg_name} (versions: {node.get('vulnerableVersionRange')})."
        if patched_version: line += f" Patched in: {patched_version}."
        reco_lines.append(line)
    return " ".join(reco_lines)

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
                
                # Fetch Staged Data
                cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE vendor_name=%s AND processed=false", (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info("No new GitHub records to process.")
                    return

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()
                
                for staging_id, raw_data in tqdm(rows, desc="Parsing GitHub Data"):
                    advisory_id = raw_data.get('ghsaId')
                    if not advisory_id: continue

                    # 1. Advisories
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get('summary'),
                        raw_data.get('severity'), parse_date(raw_data.get('publishedAt')),
                        parse_date(raw_data.get('updatedAt')), raw_data.get('permalink')
                    )

                    cve_id = next((i['value'] for i in raw_data.get('identifiers', []) if i.get('type') == 'CVE'), None)
                    if not cve_id: continue
                    
                    cvss = raw_data.get('cvss', {}) or {}
                    cwe_id = next((edge['node']['cweId'] for edge in raw_data.get('cwes', {}).get('edges', []) if edge.get('node')), None)
                    
                    cve_key = (vendor_id, cve_id)

                    # 2. CVEs
                    cves[cve_key] = (
                        vendor_id, cve_id, cwe_id, raw_data.get('description'),
                        raw_data.get('severity'), cvss.get('score'), cvss.get('vectorString'),
                        parse_date(raw_data.get('publishedAt')), parse_date(raw_data.get('updatedAt')),
                        raw_data.get('permalink')
                    )
                    
                    # 3. Map
                    advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                    # 4. Product Map
                    cve_product_maps[cve_key] = (
                        vendor_id, cve_id, None, build_recommendations(raw_data.get('vulnerabilities'))
                    )
                        
                logger.info(f"Performing bulk inserts for {len(cves)} CVEs and {len(advisories)} advisories...")
                
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
                        cvss_score=EXCLUDED.cvss_score, 
                        cvss_vector=EXCLUDED.cvss_vector, 
                        latest_update_date=EXCLUDED.latest_update_date,
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
                logger.info(f"✅ Normalization complete for {len(rows)} staged records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()



""" # github_normal.py (Production Version)
import os
import logging
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from tqdm import tqdm
from datetime import datetime

# --- Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("github_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "GitHub"

# --- Helper Functions (from your team's script) ---
def parse_date(date_string):
    if not date_string: return None
    try: return datetime.fromisoformat(date_string.replace('Z', '+00:00')).date()
    except (ValueError, TypeError): return None

def build_recommendations(vulnerabilities):
    if not vulnerabilities: return "No specific package information provided."
    reco_lines = ["Affected packages:"]
    for edge in vulnerabilities.get('edges', []):
        node = edge.get('node', {})
        pkg_name = (node.get('package', {}) or {}).get('name')
        patched_version = (node.get('firstPatchedVersion', {}) or {}).get('identifier')
        line = f"- {pkg_name} (versions: {node.get('vulnerableVersionRange')})."
        if patched_version: line += f" Patched in: {patched_version}."
        reco_lines.append(line)
    return " ".join(reco_lines)

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
                    logger.info("No new GitHub records to process.")
                    return

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()
                
                for staging_id, raw_data in tqdm(rows, desc="Parsing GitHub Data"):
                    advisory_id = raw_data.get('ghsaId')
                    if not advisory_id: continue

                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get('summary'),
                        raw_data.get('severity'), parse_date(raw_data.get('publishedAt')),
                        parse_date(raw_data.get('updatedAt')), raw_data.get('permalink')
                    )

                    cve_id = next((i['value'] for i in raw_data.get('identifiers', []) if i.get('type') == 'CVE'), None)
                    if not cve_id: continue
                    
                    cvss = raw_data.get('cvss', {}) or {}
                    cwe_id = next((edge['node']['cweId'] for edge in raw_data.get('cwes', {}).get('edges', []) if edge.get('node')), None)
                    
                    cves[(vendor_id, cve_id)] = (
                        vendor_id, cve_id, cwe_id, raw_data.get('description'),
                        raw_data.get('severity'), cvss.get('score'), cvss.get('vectorString'),
                        parse_date(raw_data.get('publishedAt')), parse_date(raw_data.get('updatedAt')),
                        raw_data.get('permalink')
                    )
                    advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                    # cve_product_map - affected_products_cpe is NULL
                    cve_product_maps[(vendor_id, cve_id)] = (
                        vendor_id, cve_id, None, build_recommendations(raw_data.get('vulnerabilities'))
                    )
                        
                logger.info(f"Performing bulk inserts for {len(cves)} CVEs and {len(advisories)} advisories...")
                if advisories: execute_values(cur, "INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, latest_update_date=EXCLUDED.latest_update_date;", list(advisories.values()))
                if cves: execute_values(cur, "INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET cwe_id=EXCLUDED.cwe_id, description=EXCLUDED.description, severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score, cvss_vector=EXCLUDED.cvss_vector, latest_update_date=EXCLUDED.latest_update_date;", list(cves.values()))
                if cve_product_maps: execute_values(cur, "INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations=EXCLUDED.recommendations;", list(cve_product_maps.values()))
                if advisory_cves_map: execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cves_map))

                processed_ids = tuple(row[0] for row in rows)
                if processed_ids: cur.execute("UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} staged records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main() """
# microsoft_normal.py (Final Production Version)
import os
import logging
import psycopg2
import sys
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from tqdm import tqdm
from datetime import datetime

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("microsoft_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "Microsoft"

# --- Helper Functions ---
def parse_date(date_string):
    if not date_string or date_string.startswith("0001-"): return None
    try: return datetime.fromisoformat(date_string.replace("Z", "+00:00")).date()
    except (ValueError, TypeError): return None

def get_ms_description(vuln_notes):
    if not isinstance(vuln_notes, list): return None
    for note_type in ["Description", "Summary", "Details"]:
        desc = next((n.get("Value") for n in vuln_notes if isinstance(n, dict) and n.get("Type") == note_type), None)
        if desc: return desc
    return None

def get_highest_severity(vulns):
    severities = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1}
    max_level, highest_severity = 0, None
    if not isinstance(vulns, list): vulns = [vulns]
    for vuln in vulns:
        threats = vuln.get("Threats", [])
        if not isinstance(threats, list): threats = [threats]
        for threat in threats:
            if isinstance(threat, dict) and threat.get("Type") == 3:
                desc = threat.get("Description", {}).get("Value")
                if desc in severities and severities[desc] > max_level:
                    max_level, highest_severity = severities[desc], desc
    return highest_severity

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
                cur.execute("SELECT staging_id, raw_data, source_url FROM vendor_staging_table WHERE vendor_name=%s AND processed=false", (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info("No new Microsoft records to process.")
                    return

                logger.info(f"Normalizing {len(rows)} records...")
                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data, source_url in tqdm(rows, desc="Parsing Microsoft Data"):
                    tracking = raw_data.get('DocumentTracking', {})
                    advisory_id = tracking.get("Identification", {}).get("ID", {}).get("Value")
                    if not advisory_id: continue

                    vulns = raw_data.get("Vulnerability", [])

                    ref_url = next(
                        (ref.get("URL") for ref in raw_data.get("DocumentReferences", [])
                        if isinstance(ref, dict) and ref.get("URL")),
                        source_url  # fallback if not found
                    )

                    # 1. Advisory
                    advisories[advisory_id] = (
                        advisory_id, vendor_id,
                        raw_data.get("DocumentTitle", {}).get("Value"),
                        get_highest_severity(vulns),
                        parse_date(tracking.get("InitialReleaseDate")),
                        parse_date(tracking.get("CurrentReleaseDate")),
                        ref_url
                    )

                    for vuln in vulns:
                        cve_id = vuln.get("CVE")
                        if not cve_id: continue

                        ms_desc = get_ms_description(vuln.get("Notes", []))
                        ms_cwe = next((cwe.get("Value") for cwe in vuln.get("CWEs", []) if isinstance(cwe, dict)), None)
                        
                        cve_initial_date = parse_date(vuln.get("InitialReleaseDate")) or parse_date(tracking.get("InitialReleaseDate"))
                        cve_latest_date = parse_date(vuln.get("CurrentReleaseDate")) or parse_date(tracking.get("CurrentReleaseDate"))
                        ms_score, ms_vector = None, None
                        if scores := vuln.get("CVSSScoreSets"):
                            for score_set in sorted(scores, key=lambda x: x.get('Version', '0.0'), reverse=True):
                                ms_score, ms_vector = score_set.get("BaseScore"), score_set.get("Vector")
                                if ms_score: break
                        
                        cve_key = (vendor_id, cve_id)
                        
                        # 2. CVE
                        cves[cve_key] = (
                            vendor_id, cve_id, ms_cwe, ms_desc,
                            get_highest_severity([vuln]),
                            ms_score, ms_vector,
                            cve_initial_date, cve_latest_date,
                            ref_url
                        )
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))
                        
                        # 3. Product Map
                        recommendations = next((n.get("Value") for n in vuln.get("Notes", []) if isinstance(n, dict) and n.get("Type") == "Details"), "See advisory URL.")
                        cve_product_maps[cve_key] = (
                            vendor_id, cve_id, None, recommendations
                        )

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
                        cwe_id=COALESCE(EXCLUDED.cwe_id, cves.cwe_id),
                        description=COALESCE(EXCLUDED.description, cves.description), 
                        severity=COALESCE(EXCLUDED.severity, cves.severity), 
                        cvss_score=COALESCE(EXCLUDED.cvss_score, cves.cvss_score), 
                        cvss_vector=COALESCE(EXCLUDED.cvss_vector, cves.cvss_vector),
                        initial_release_date = EXCLUDED.initial_release_date, 
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
                logger.info(f"✅ Normalization complete for {len(rows)} Microsoft records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()




'''
# microsoft_normal.py (Production Version)
import os
import logging
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from tqdm import tqdm
from datetime import datetime

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("microsoft_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "Microsoft"

# --- Helper Functions (from your team's script) ---
def parse_date(date_string):
    if not date_string or date_string.startswith("0001-"): return None
    try: return datetime.fromisoformat(date_string.replace("Z", "+00:00")).date()
    except (ValueError, TypeError): return None

def get_ms_description(vuln_notes):
    if not isinstance(vuln_notes, list): return None
    for note_type in ["Description", "Summary", "Details"]:
        desc = next((n.get("Value") for n in vuln_notes if isinstance(n, dict) and n.get("Type") == note_type), None)
        if desc: return desc
    return None

def get_highest_severity(vulns):
    severities = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1}
    max_level, highest_severity = 0, None
    if not isinstance(vulns, list): vulns = [vulns]
    for vuln in vulns:
        threats = vuln.get("Threats", [])
        if not isinstance(threats, list): threats = [threats]
        for threat in threats:
            if isinstance(threat, dict) and threat.get("Type") == 3:
                desc = threat.get("Description", {}).get("Value")
                if desc in severities and severities[desc] > max_level:
                    max_level, highest_severity = severities[desc], desc
    return highest_severity

# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]
                
                cur.execute("SELECT staging_id, raw_data, source_url FROM vendor_staging_table WHERE vendor_name=%s AND processed=false", (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info("No new Microsoft records to process.")
                    return

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data, source_url in tqdm(rows, desc="Parsing Microsoft Data"):
                    tracking = raw_data.get('DocumentTracking', {})
                    advisory_id = tracking.get("Identification", {}).get("ID", {}).get("Value")
                    if not advisory_id: continue

                    
                    vulns = raw_data.get("Vulnerability", [])

                    ref_url = next(
                        (ref.get("URL") for ref in raw_data.get("DocumentReferences", [])
                        if isinstance(ref, dict) and ref.get("URL")),
                        source_url  # fallback if not found
                    )
                    

                    advisories[advisory_id] = (
                        advisory_id, vendor_id,
                        raw_data.get("DocumentTitle", {}).get("Value"),
                        get_highest_severity(vulns),
                        parse_date(tracking.get("InitialReleaseDate")),
                        parse_date(tracking.get("CurrentReleaseDate")),
                        ref_url
                    )

                    for vuln in vulns:
                        cve_id = vuln.get("CVE")
                        if not cve_id: continue


                        # --- Restore correct CVE extraction ---
                        ms_desc = get_ms_description(vuln.get("Notes", []))
                        ms_cwe = next((cwe.get("Value") for cwe in vuln.get("CWEs", []) if isinstance(cwe, dict)), None)
                        
                        cve_initial_date = parse_date(vuln.get("InitialReleaseDate")) or parse_date(tracking.get("InitialReleaseDate"))
                        cve_latest_date = parse_date(vuln.get("CurrentReleaseDate")) or parse_date(tracking.get("CurrentReleaseDate"))
                        ms_score, ms_vector = None, None
                        if scores := vuln.get("CVSSScoreSets"):
                            for score_set in sorted(scores, key=lambda x: x.get('Version', '0.0'), reverse=True):
                                ms_score, ms_vector = score_set.get("BaseScore"), score_set.get("Vector")
                                if ms_score: break
                        
                        # CVE record - cwe_id is NULL
                        cves[(vendor_id, cve_id)] = (
                            vendor_id, cve_id, ms_cwe, ms_desc,
                            get_highest_severity([vuln]),
                            ms_score, ms_vector,
                            cve_initial_date, cve_latest_date,
                            ref_url
                        )
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))
                        
                        recommendations = next((n.get("Value") for n in vuln.get("Notes", []) if isinstance(n, dict) and n.get("Type") == "Details"), "See advisory URL.")
                        cve_product_maps[(vendor_id, cve_id)] = (vendor_id, cve_id, None, recommendations)

                logger.info("Performing bulk database inserts...")
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories 
                        (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                        VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET 
                            title = EXCLUDED.title, 
                            severity = EXCLUDED.severity, 
                            latest_update_date = EXCLUDED.latest_update_date, 
                            advisory_url = EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET
                            cwe_id = EXCLUDED.cwe_id,
                            description = EXCLUDED.description,
                            severity = EXCLUDED.severity,
                            cvss_score = EXCLUDED.cvss_score,
                            cvss_vector = EXCLUDED.cvss_vector,
                            initial_release_date = EXCLUDED.initial_release_date,
                            latest_update_date = EXCLUDED.latest_update_date,
                            reference_url = EXCLUDED.reference_url;
                    """, list(cves.values()))

                if cve_product_maps: execute_values(cur, "INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations=EXCLUDED.recommendations;", list(cve_product_maps.values()))
                if advisory_cves_map: execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cves_map))

                processed_ids = tuple(row[0] for row in rows)
                if processed_ids: cur.execute("UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} Microsoft records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()
'''

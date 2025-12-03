# suse_normal.py (Final Production Version)
import os
import logging
import json
from datetime import datetime
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from tqdm import tqdm
import xml.etree.ElementTree as ET
import sys

# --- Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("suse_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "OpenSUSE"
NS = {
    'cvrf': 'http://www.icasi.org/CVRF/schema/cvrf/1.1',
    'vuln': 'http://www.icasi.org/CVRF/schema/vuln/1.1'
}

# --- Helper Functions ---
def parse_date(date_string):
    if not date_string: return None
    try: return datetime.fromisoformat(date_string.replace('Z', '+00:00')).date()
    except (ValueError, TypeError): return None

def find_text(element, path):
    if element is None: return None
    el = element.find(path, NS)
    return " ".join(t.strip() for t in el.itertext() if t and t.strip()) if el is not None else None

def get_vuln_description(vuln_el):
    for tag in ["Description", "Details", "Summary", "Vulnerability Description"]:
        note = vuln_el.find(f'vuln:Notes/vuln:Note[@Title="{tag}"]', NS)
        if note is not None:
            return find_text(note, '.')
    return find_text(vuln_el, 'vuln:Notes/vuln:Note')

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
                    logger.info("No new SUSE records to process.")
                    return

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data, source_url in tqdm(rows, desc="Parsing XML Records"):     
                    if isinstance(raw_data, str):
                        try:
                            raw_data = json.loads(raw_data)
                        except Exception:
                            logger.warning(f"⚠️ Could not parse raw_data for staging_id={staging_id}")
                            continue

                    xml_content = raw_data.get('xml_content')
                    if not xml_content:
                        continue

                    try:
                        root = ET.fromstring(xml_content)
                        advisory_id = find_text(root, 'cvrf:DocumentTracking/cvrf:Identification/cvrf:ID')
                        if not advisory_id: continue

                        advisory_severity = find_text(root, './/vuln:Threats/vuln:Threat[@Type="Impact"]/vuln:Description')

                        # 1. Advisory Record
                        advisories[advisory_id] = (
                            advisory_id, vendor_id, find_text(root, 'cvrf:DocumentTitle'),
                            find_text(root, './/vuln:Description'),  # optional severity fallback
                            parse_date(find_text(root, 'cvrf:DocumentTracking/cvrf:InitialReleaseDate')),
                            parse_date(find_text(root, 'cvrf:DocumentTracking/cvrf:CurrentReleaseDate')),
                            source_url
                        )

                        for vuln in root.findall('vuln:Vulnerability', NS):
                            cve_id = find_text(vuln, 'vuln:CVE')
                            if not cve_id: continue

                            description = get_vuln_description(vuln)
                            severity = find_text(vuln, 'vuln:Threats/vuln:Threat[@Type="Impact"]/vuln:Description')
                            score = find_text(vuln, 'vuln:CVSSScoreSets/vuln:ScoreSet/vuln:BaseScore')
                            vector = find_text(vuln, 'vuln:CVSSScoreSets/vuln:ScoreSet/vuln:Vector')
                            remediation_note = find_text(vuln, 'vuln:Remediations/vuln:Remediation/vuln:Description')

                            cve_key = (vendor_id, cve_id)
                            
                            # 2. CVE Record
                            cves[cve_key] = (
                                vendor_id, cve_id, 
                                None, # cwe_id
                                description, severity,
                                score, vector,
                                parse_date(find_text(root, 'cvrf:DocumentTracking/cvrf:InitialReleaseDate')),
                                parse_date(find_text(root, 'cvrf:DocumentTracking/cvrf:CurrentReleaseDate')),
                                source_url
                            )

                            # 3. Product Map
                            cve_product_maps[cve_key] = (
                                vendor_id, cve_id, None, remediation_note or description or "See advisory URL."
                            )

                            # 4. Map
                            advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                    except ET.ParseError as e:
                        logger.error(f"Failed to parse XML for staging_id {staging_id}: {e}")

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
                logger.info(f"✅ Normalization complete for {len(rows)} SUSE records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()

'''
# suse_normal.py (Production Version)
import os
import logging
import json
from datetime import datetime
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from tqdm import tqdm
import xml.etree.ElementTree as ET

# --- Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("suse_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "OpenSUSE"
NS = {
    'cvrf': 'http://www.icasi.org/CVRF/schema/cvrf/1.1',
    'vuln': 'http://www.icasi.org/CVRF/schema/vuln/1.1'
}

# --- Helper Functions ---
def parse_date(date_string):
    if not date_string: return None
    try: return datetime.fromisoformat(date_string.replace('Z', '+00:00')).date()
    except (ValueError, TypeError): return None

def find_text(element, path):
    if element is None: return None
    el = element.find(path, NS)
    return " ".join(t.strip() for t in el.itertext() if t and t.strip()) if el is not None else None

def get_vuln_description(vuln_el):
    for tag in ["Description", "Details", "Summary", "Vulnerability Description"]:
        note = vuln_el.find(f'vuln:Notes/vuln:Note[@Title="{tag}"]', NS)
        if note is not None:
            return find_text(note, '.')
    return find_text(vuln_el, 'vuln:Notes/vuln:Note')

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
                    logger.info("No new SUSE records to process.")
                    return

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data, source_url in tqdm(rows, desc="Parsing XML Records"):     
                    if isinstance(raw_data, str):
                        try:
                            raw_data = json.loads(raw_data)
                        except Exception:
                            logger.warning(f"⚠️ Could not parse raw_data for staging_id={staging_id}")
                            continue

                    xml_content = raw_data.get('xml_content')
                    if not xml_content:
                        continue

                    try:
                        root = ET.fromstring(xml_content)
                        advisory_id = find_text(root, 'cvrf:DocumentTracking/cvrf:Identification/cvrf:ID')
                        if not advisory_id: continue

                        advisory_severity = find_text(root, './/vuln:Threats/vuln:Threat[@Type="Impact"]/vuln:Description')


                        advisories[advisory_id] = (
                            advisory_id, vendor_id, find_text(root, 'cvrf:DocumentTitle'),
                            find_text(root, './/vuln:Description'),  # optional severity fallback
                            parse_date(find_text(root, 'cvrf:DocumentTracking/cvrf:InitialReleaseDate')),
                            parse_date(find_text(root, 'cvrf:DocumentTracking/cvrf:CurrentReleaseDate')),
                            source_url
                        )


                        for vuln in root.findall('vuln:Vulnerability', NS):
                            cve_id = find_text(vuln, 'vuln:CVE')
                            if not cve_id:
                                continue

                            description = get_vuln_description(vuln)
                            severity = find_text(vuln, 'vuln:Threats/vuln:Threat[@Type="Impact"]/vuln:Description')
                            score = find_text(vuln, 'vuln:CVSSScoreSets/vuln:ScoreSet/vuln:BaseScore')
                            vector = find_text(vuln, 'vuln:CVSSScoreSets/vuln:ScoreSet/vuln:Vector')

                            ref_url = source_url

                            remediation_note = find_text(vuln, 'vuln:Remediations/vuln:Remediation/vuln:Description')

                            cves[(vendor_id, cve_id)] = (
                                vendor_id, cve_id, None, description, severity,
                                score, vector,
                                parse_date(find_text(root, 'cvrf:DocumentTracking/cvrf:InitialReleaseDate')),
                                parse_date(find_text(root, 'cvrf:DocumentTracking/cvrf:CurrentReleaseDate')),
                                source_url
                            )

                            cve_product_maps[(vendor_id, cve_id)] = (
                                vendor_id, cve_id, None, remediation_note or description or "See advisory URL."
                            )

                            advisory_cves_map.add((advisory_id, vendor_id, cve_id))


                    except ET.ParseError as e:
                        logger.error(f"Failed to parse XML for staging_id {staging_id}: {e}")

                logger.info("Performing bulk inserts...")
                if advisories:
                    execute_values(cur, 
                        """
                        INSERT INTO advisories (
                            advisory_id, vendor_id, title, severity, 
                            initial_release_date, latest_update_date, advisory_url
                        ) 
                        VALUES %s 
                        ON CONFLICT (advisory_id) DO UPDATE 
                        SET 
                            title = EXCLUDED.title,
                            severity = EXCLUDED.severity,
                            latest_update_date = EXCLUDED.latest_update_date,
                            advisory_url = EXCLUDED.advisory_url;
                        """,
                        list(advisories.values())
                    )

                if cves:
                    execute_values(cur, """
                    INSERT INTO cves (
                        vendor_id, cve_id, cwe_id, description, severity, 
                        cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url
                    ) 
                    VALUES %s 
                    ON CONFLICT (vendor_id, cve_id) DO UPDATE 
                    SET 
                        description = EXCLUDED.description,
                        severity = EXCLUDED.severity,
                        cvss_score = EXCLUDED.cvss_score,
                        cvss_vector = EXCLUDED.cvss_vector,
                        reference_url = EXCLUDED.reference_url;
                """, list(cves.values()))

                if cve_product_maps: execute_values(cur, "INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations=EXCLUDED.recommendations;", list(cve_product_maps.values()))
                if advisory_cves_map: execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cves_map))

                processed_ids = tuple(row[0] for row in rows)
                if processed_ids: cur.execute("UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} SUSE records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()
    '''
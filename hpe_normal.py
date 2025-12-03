# HPE_normal.py (Final Production Version)
import os
import logging
import psycopg2
import sys
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv
from datetime import datetime
import re

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("hpe_normalizer")
load_dotenv()

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS")
}
VENDOR_NAME = "HPE"

# --- Helper Functions ---
def parse_date(date_str):
    if not date_str or not isinstance(date_str, str):
        return None
    for fmt in ("%d %b %Y", "%Y-%m-%d", "%m/%d/%Y %H:%M:%S.%f"):
        try:
            return datetime.strptime(date_str.strip(), fmt).date()
        except (ValueError, TypeError):
            continue
    return None

def safe_float(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return None

def extract_recommendations(references_list):
    rec_map = {}
    if not isinstance(references_list, list):
        return rec_map

    for ref in references_list:
        match = re.match(r"(CVE-\d{4}-\d+)\s*[-–]\s*(.*)", ref)
        if match:
            cve_id, desc = match.groups()
            rec_map[cve_id.strip()] = desc.strip()
    return rec_map

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

                logger.info(f"Normalizing {len(rows)} records...")
                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in rows:
                    advisory_id = raw_data.get("advisory_id")
                    if not advisory_id: continue

                    meta = raw_data.get("metadata_page", {})
                    release_date = parse_date(meta.get("release_date"))
                    last_updated = parse_date(meta.get("last_updated"))

                    advisory_severity = (
                        raw_data.get("severity", ["Unknown"])[0]
                        if isinstance(raw_data.get("severity"), list)
                        else raw_data.get("severity", "Unknown")
                    )

                    # 1. Advisory
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("title"),
                        advisory_severity, release_date, last_updated,
                        raw_data.get("official_link")
                    )

                    recommendations_map = extract_recommendations(raw_data.get("references", []))

                    for cv in raw_data.get("cvss_scores", []):
                        cve_id = cv.get("reference")
                        if not cve_id: continue

                        cve_key = (vendor_id, cve_id)
                        
                        # 2. CVE
                        cves[cve_key] = (
                            vendor_id, cve_id, 
                            None, None, None, # cwe, desc, sev
                            safe_float(cv.get("base_score")),
                            cv.get("vector"),
                            None, None, # dates
                            raw_data.get("official_link")
                        )

                        # 3. Product Map
                        recommendations = recommendations_map.get(cve_id)
                        cve_product_maps[cve_key] = (
                            vendor_id, cve_id, None, recommendations
                        )
                        
                        # 4. Map
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

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
# HPE_normal.py (Production Version - Updated for New Raw Schema)
import os
import logging
import psycopg2
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv
from datetime import datetime
import re

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("hpe_normalizer")
load_dotenv()

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS")
}
VENDOR_NAME = "HPE"

# --- Helper Functions ---
def parse_date(date_str):
    if not date_str or not isinstance(date_str, str):
        return None
    for fmt in ("%d %b %Y", "%Y-%m-%d", "%m/%d/%Y %H:%M:%S.%f"):
        try:
            return datetime.strptime(date_str.strip(), fmt).date()
        except (ValueError, TypeError):
            continue
    logger.warning(f"Could not parse date string: {date_str}")
    return None

def safe_float(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return None

def extract_recommendations(references_list):
    """Extract mitigation or recommendation text from references."""
    rec_map = {}
    if not isinstance(references_list, list):
        return rec_map

    for ref in references_list:
        match = re.match(r"(CVE-\d{4}-\d+)\s*[-–]\s*(.*)", ref)
        if match:
            cve_id, desc = match.groups()
            rec_map[cve_id.strip()] = desc.strip()
    return rec_map

# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO vendors (vendor_name)
                    VALUES (%s)
                    ON CONFLICT (vendor_name) DO NOTHING;
                """, (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                cur.execute("""
                    SELECT staging_id, raw_data
                    FROM vendor_staging_table
                    WHERE vendor_name=%s AND processed=false
                """, (VENDOR_NAME,))
                rows = cur.fetchall()

                if not rows:
                    logger.info(f"No new {VENDOR_NAME} records to process.")
                    return

                logger.info(f"Normalizing {len(rows)} records...")
                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in rows:
                    advisory_id = raw_data.get("advisory_id")
                    if not advisory_id:
                        continue

                    meta = raw_data.get("metadata_page", {})
                    release_date = parse_date(meta.get("release_date"))
                    last_updated = parse_date(meta.get("last_updated"))

                    advisory_severity = (
                        raw_data.get("severity", ["Unknown"])[0]
                        if isinstance(raw_data.get("severity"), list)
                        else raw_data.get("severity", "Unknown")
                    )

                    advisories[advisory_id] = (
                        advisory_id,
                        vendor_id,
                        raw_data.get("title"),
                        advisory_severity,
                        release_date,
                        last_updated,
                        raw_data.get("official_link")
                    )

                    # Extract recommendations per CVE
                    recommendations_map = extract_recommendations(raw_data.get("references", []))

                    cve_list = raw_data.get("cvss_scores", [])
                    for cv in cve_list:
                        cve_id = cv.get("reference")
                        if not cve_id:
                            continue

                        cve_key = (vendor_id, cve_id)
                        cves[cve_key] = (
                            vendor_id,
                            cve_id,
                            None,  # cwe_id
                            None,
                            None,
                            safe_float(cv.get("base_score")),
                            cv.get("vector"),
                            None,
                            None,
                            raw_data.get("official_link")
                        )

                        # Map product + recommendation
                        recommendations = recommendations_map.get(cve_id)


                        cve_product_maps[cve_key] = (
                            vendor_id,
                            cve_id,
                            None,
                            recommendations
                        )

                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                # --- Bulk Inserts ---
                logger.info("Performing bulk database inserts...")

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity,
                            initial_release_date, latest_update_date, advisory_url)
                        VALUES %s
                        ON CONFLICT (advisory_id)
                        DO UPDATE SET
                            title=EXCLUDED.title,
                            severity=EXCLUDED.severity,
                            latest_update_date=EXCLUDED.latest_update_date;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity,
                            cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET
                            description=EXCLUDED.description,
                            severity=EXCLUDED.severity,
                            cvss_score=EXCLUDED.cvss_score,
                            cvss_vector=EXCLUDED.cvss_vector,
                            latest_update_date=EXCLUDED.latest_update_date;
                    """, list(cves.values()))

                if cve_product_maps:
                    execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO NOTHING;
                    """, list(cve_product_maps.values()))

                if advisory_cves_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id)
                        VALUES %s
                        ON CONFLICT DO NOTHING;
                    """, list(advisory_cves_map))

                processed_ids = tuple(row[0] for row in rows)
                if processed_ids:
                    cur.execute("""
                        UPDATE vendor_staging_table
                        SET processed = TRUE, processed_at = NOW()
                        WHERE staging_id IN %s;
                    """, (processed_ids,))

                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)


if __name__ == "__main__":
    main()
'''
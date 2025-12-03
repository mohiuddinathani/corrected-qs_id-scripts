# gitlab_normal.py (Final Production Version)
import os
import re
import logging
import sys
import psycopg2
from psycopg2.extras import execute_values, Json
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("gitlab_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "GitLab"

# --- Helper Functions ---
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

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    # Use source_url as advisory ID if no specific ID is provided
                    advisory_id = raw_data.get("source_url")
                    if not advisory_id:
                        continue
                    
                    cve_id = raw_data.get("cve_id")
                    if not cve_id:
                        continue

                    # --- Derive Severity ---
                    score = raw_data.get("cvss_score")
                    try:
                        score = float(score) if score else None
                    except:
                        score = None
                    
                    severity = None
                    if score is not None:
                        if score >= 9.0: severity = "Critical"
                        elif score >= 7.0: severity = "High"
                        elif score >= 4.0: severity = "Medium"
                        elif score > 0: severity = "Low"

                    # 1. Advisory Record
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("title"),
                        severity,
                        parse_date(raw_data.get("published_date")),
                        None, # Latest update
                        raw_data.get("source_url")
                    )

                    # 2. CVE Record
                    weakness = raw_data.get("weakness")
                    if isinstance(weakness, list):
                        weakness = ",".join(weakness)

                    cve_key = (vendor_id, cve_id)
                    cves[cve_key] = (
                        vendor_id, cve_id, 
                        weakness,
                        raw_data.get("description"),
                        severity,
                        raw_data.get("cvss_score"),
                        raw_data.get("cvss_vector"),
                        None, None, # dates
                        raw_data.get("source_url")
                    )

                    # 3. Product Map
                    cve_product_maps[cve_key] = (
                        vendor_id, cve_id, 
                        None, # affected_products_cpe
                        raw_data.get("solution") or "See advisory URL for details."
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
                        initial_release_date=EXCLUDED.initial_release_date,
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
                        cvss_score=EXCLUDED.cvss_score, 
                        cvss_vector=EXCLUDED.cvss_vector, 
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
import os
import re
import logging
import psycopg2
from psycopg2.extras import execute_values, Json
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("gitlab_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "GitLab"

# --- Helper Functions ---
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

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    advisory_id = raw_data.get("source_url")  # ✅ fixed key
                    if not advisory_id:
                        continue
                    
                    cve_id = raw_data.get("cve_id")
                    if not cve_id:
                        continue

                    # --- derive severity ---
                    score = raw_data.get("cvss_score")
                    try:
                        score = float(score) if score else None
                    except:
                        score = None
                    
                    severity = None
                    if score is not None:
                        if score >= 9.0:
                            severity = "Critical"
                        elif score >= 7.0:
                            severity = "High"
                        elif score >= 4.0:
                            severity = "Medium"
                        elif score > 0:
                            severity = "Low"

                    # --- Advisory ---
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("title"),
                        severity,
                        parse_date(raw_data.get("published_date")),
                        None,
                        raw_data.get("source_url")
                    )

                    # --- CVE ---
                    cves[(vendor_id, cve_id)] = (
                        vendor_id, cve_id, ",".join(raw_data.get("weakness", [])) if isinstance(raw_data.get("weakness"), list) else raw_data.get("weakness"),
                        raw_data.get("description"),
                        severity,
                        raw_data.get("cvss_score"),
                        raw_data.get("cvss_vector"),
                        None, None,
                        raw_data.get("source_url")
                    )

                    # --- CVE product mapping ---
                    cve_product_maps[(vendor_id, cve_id)] = (vendor_id, cve_id, 
                        None,
                        raw_data.get("solution") or "See advisory URL for details.")
                    advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE 
                        SET title=EXCLUDED.title, severity=EXCLUDED.severity, initial_release_date=EXCLUDED.initial_release_date;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE 
                        SET cwe_id=EXCLUDED.cwe_id, description=EXCLUDED.description, severity=EXCLUDED.severity, 
                            cvss_score=EXCLUDED.cvss_score, cvss_vector=EXCLUDED.cvss_vector, reference_url=EXCLUDED.reference_url;
                    """, list(cves.values()))

                if cve_product_maps:
                    execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations=EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))

                if advisory_cves_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id)
                        VALUES %s
                        ON CONFLICT DO NOTHING;
                    """, list(advisory_cves_map))

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
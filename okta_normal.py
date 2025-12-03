# Okta_normal.py (Final Production Version)
import os
import re
import logging
import psycopg2
import sys
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("okta_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Okta"

# --- Helper ---
def extract_cvss(cvss_text):
    if not cvss_text:
        return None, None
    score_match = re.search(r"([\d.]+)/10", cvss_text)
    vector_match = re.search(r"\((CVSS:[^)]+)\)", cvss_text)
    return (
        float(score_match.group(1)) if score_match else None,
        vector_match.group(1).strip() if vector_match else None
    )

# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                # Ensure vendor exists
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                # Get all unprocessed staging rows
                cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE vendor_name=%s AND processed=false;", (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info(f"No new {VENDOR_NAME} records to process.")
                    return

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    cves_list = raw_data.get("cves", [])
                    if not cves_list:
                        continue

                    cvss_score, cvss_vector = extract_cvss(raw_data.get("cvss"))

                    for cve_id in cves_list:
                        if not cve_id:
                            continue

                        # Advisory ID is derived from each CVE
                        advisory_id = f"OKTA-{cve_id}"

                        # --- Advisory record ---
                        advisories[advisory_id] = (
                            advisory_id, vendor_id, raw_data.get("title"),
                            None, None, None,  # severity, dates
                            raw_data.get("advisory_url") or raw_data.get("url")
                        )

                        # --- CVE record ---
                        cves[(vendor_id, cve_id)] = (
                            vendor_id, cve_id,
                            None,  # cwe_id
                            raw_data.get("vulnerability_details"),
                            None,  # severity
                            cvss_score, cvss_vector,
                            raw_data.get("initial_release_date"),
                            raw_data.get("latest_update_date"),
                            raw_data.get("advisory_url") or raw_data.get("url")
                        )

                        # --- CVE product map ---
                        cve_product_maps[(vendor_id, cve_id)] = (
                            vendor_id, cve_id, None,
                            raw_data.get("resolution") or "See advisory for mitigation steps."
                        )

                        # --- Advisory-CVE link ---
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date,
                                                latest_update_date, advisory_url)
                        VALUES %s
                        ON CONFLICT (advisory_id)
                        DO UPDATE SET title=EXCLUDED.title, advisory_url=EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity,
                                          cvss_score, cvss_vector, initial_release_date,
                                          latest_update_date, reference_url)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET description=COALESCE(EXCLUDED.description, cves.description),
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
                        ON CONFLICT (vendor_id, cve_id) 
                        DO UPDATE SET recommendations=EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))

                if advisory_cves_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id)
                        VALUES %s
                        ON CONFLICT DO NOTHING;
                    """, list(advisory_cves_map))

                # Mark Processed + Timestamp
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
# Okta_normal.py (Production Version - Fixed for list of CVEs)
import os
import re
import logging
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("okta_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Okta"

# --- Helper ---
def extract_cvss(cvss_text):
    if not cvss_text:
        return None, None
    score_match = re.search(r"([\d.]+)/10", cvss_text)
    vector_match = re.search(r"\((CVSS:[^)]+)\)", cvss_text)
    return (
        float(score_match.group(1)) if score_match else None,
        vector_match.group(1).strip() if vector_match else None
    )

# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                # Ensure vendor exists
                cur.execute("""
                    INSERT INTO vendors (vendor_name)
                    VALUES (%s)
                    ON CONFLICT (vendor_name) DO NOTHING;
                """, (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                # Get all unprocessed staging rows
                cur.execute("""
                    SELECT staging_id, raw_data
                    FROM vendor_staging_table
                    WHERE vendor_name=%s AND processed=false;
                """, (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info(f"No new {VENDOR_NAME} records to process.")
                    return

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    cves_list = raw_data.get("cves", [])
                    if not cves_list:
                        continue

                    cvss_score, cvss_vector = extract_cvss(raw_data.get("cvss"))

                    for cve_id in cves_list:
                        if not cve_id:
                            continue

                        # Advisory ID is derived from each CVE
                        advisory_id = f"OKTA-{cve_id}"

                        # --- Advisory record ---
                        advisories[advisory_id] = (
                            advisory_id, vendor_id, raw_data.get("title"),
                            None, None, None,  # severity, dates
                            raw_data.get("advisory_url") or raw_data.get("url")
                        )

                        # --- CVE record ---
                        cves[(vendor_id, cve_id)] = (
                            vendor_id, cve_id,
                            None,  # cwe_id
                            raw_data.get("vulnerability_details"),
                            None,  # severity
                            cvss_score, cvss_vector,
                            raw_data.get("initial_release_date"),
                            raw_data.get("latest_update_date"),
                            raw_data.get("advisory_url") or raw_data.get("url")
                        )

                        # --- CVE product map ---
                        cve_product_maps[(vendor_id, cve_id)] = (
                            vendor_id, cve_id, None,
                            raw_data.get("resolution") or "See advisory for mitigation steps."
                        )

                        # --- Advisory-CVE link ---
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date,
                                                latest_update_date, advisory_url)
                        VALUES %s
                        ON CONFLICT (advisory_id)
                        DO UPDATE SET title=EXCLUDED.title, advisory_url=EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity,
                                          cvss_score, cvss_vector, initial_release_date,
                                          latest_update_date, reference_url)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET description=EXCLUDED.description,
                                      cvss_score=EXCLUDED.cvss_score,
                                      cvss_vector=EXCLUDED.cvss_vector,
                                      reference_url=EXCLUDED.reference_url;
                    """, list(cves.values()))

                if cve_product_maps:
                    execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET recommendations=EXCLUDED.recommendations;
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
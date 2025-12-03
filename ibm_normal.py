# IBM_normal.py (Final Production Version)
import os
import json
import re
import logging
import psycopg2
import sys
from psycopg2.extras import execute_values, Json
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("ibm_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "IBM"

# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                # Ensure vendor entry exists
                cur.execute("""
                    INSERT INTO vendors (vendor_name)
                    VALUES (%s)
                    ON CONFLICT (vendor_name) DO NOTHING;
                """, (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                # Fetch all unprocessed records
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

                # --- Process Each Raw Entry ---
                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    advisory_id = raw_data.get("bulletin_id")
                    if not advisory_id:
                        continue

                    severity = raw_data.get("severity")
                    title = raw_data.get("title")
                    advisory_url = raw_data.get("advisory_url")

                    # Advisory Record
                    advisories[advisory_id] = (
                        advisory_id,
                        vendor_id,
                        title,
                        severity,
                        None,  # initial_release_date (not at advisory level)
                        None,  # latest_update_date (not at advisory level)
                        advisory_url
                    )

                    # --- CVEs ---
                    for cve_item in raw_data.get("cves", []):
                        cve_id = cve_item.get("cve_id")
                        if not cve_id:
                            continue
                        cve_id = cve_id.upper()

                        # Extract clean CWE only (e.g., CWE-79)
                        cwe_raw = cve_item.get("cwe", "")
                        match = re.search(r"\bCWE-\d+\b", str(cwe_raw), re.IGNORECASE)
                        cwe_clean = match.group(0).upper() if match else None
                        
                        cve_key = (vendor_id, cve_id)

                        cves[cve_key] = (
                            vendor_id,
                            cve_id,
                            cwe_clean,
                            cve_item.get("description"),
                            cve_item.get("severity"),
                            cve_item.get("cvss_score"),
                            cve_item.get("cvss_vector"),
                            cve_item.get("initial_release_date"),
                            cve_item.get("latest_update_date"),
                            advisory_url
                        )

                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                        # --- Product Mapping ---
                        recommendations = "See advisory for patching details."
                        
                        cve_product_maps[cve_key] = (
                            vendor_id,
                            cve_id,
                            None, # affected_products_cpe
                            recommendations
                        )

                # --- Bulk Inserts ---
                logger.info("Performing bulk inserts...")

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories
                        (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                        VALUES %s
                        ON CONFLICT (advisory_id)
                        DO UPDATE SET
                            title = EXCLUDED.title,
                            severity = EXCLUDED.severity,
                            advisory_url = EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves
                        (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector,
                         initial_release_date, latest_update_date, reference_url)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET
                            cwe_id = COALESCE(EXCLUDED.cwe_id, cves.cwe_id),
                            description = COALESCE(EXCLUDED.description, cves.description),
                            severity = COALESCE(EXCLUDED.severity, cves.severity),
                            cvss_score = COALESCE(EXCLUDED.cvss_score, cves.cvss_score),
                            cvss_vector = COALESCE(EXCLUDED.cvss_vector, cves.cvss_vector),
                            initial_release_date = EXCLUDED.initial_release_date,
                            latest_update_date = EXCLUDED.latest_update_date,
                            reference_url = EXCLUDED.reference_url;
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
                        INSERT INTO cve_product_map
                        (vendor_id, cve_id, affected_products_cpe, recommendations)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET
                            affected_products_cpe = EXCLUDED.affected_products_cpe,
                            recommendations = EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))

                if advisory_cves_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id)
                        VALUES %s
                        ON CONFLICT DO NOTHING;
                    """, list(advisory_cves_map))

                # --- Mark Processed ---
                processed_ids = tuple(row[0] for row in rows)
                if processed_ids:
                    cur.execute(
                        "UPDATE vendor_staging_table SET processed = TRUE, processed_at = NOW() WHERE staging_id IN %s;",
                        (processed_ids,)
                    )

                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} {VENDOR_NAME} records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)


if __name__ == "__main__":
    main()


'''
# IBM_normal.py (Production Version - Fully Compatible with gem.py Raw Data)
import os
import json
import re
import logging
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("ibm_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "IBM"

# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                # Ensure vendor entry exists
                cur.execute("""
                    INSERT INTO vendors (vendor_name)
                    VALUES (%s)
                    ON CONFLICT (vendor_name) DO NOTHING;
                """, (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                # Fetch all unprocessed records
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

                # --- Process Each Raw Entry ---
                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    advisory_id = raw_data.get("bulletin_id")
                    if not advisory_id:
                        continue

                    severity = raw_data.get("severity")
                    title = raw_data.get("title")
                    advisory_url = raw_data.get("advisory_url")

                    # Advisory Record
                    advisories[advisory_id] = (
                        advisory_id,
                        vendor_id,
                        title,
                        severity,
                        None,  # initial_release_date (not at advisory level)
                        None,  # latest_update_date (not at advisory level)
                        advisory_url
                    )

                    # --- CVEs ---
                    # --- CVEs ---
                    for cve_item in raw_data.get("cves", []):
                        cve_id = cve_item.get("cve_id")
                        if not cve_id:
                            continue
                        cve_id = cve_id.upper()

                        # Extract clean CWE only (e.g., CWE-79)
                        cwe_raw = cve_item.get("cwe", "")
                        match = re.search(r"\bCWE-\d+\b", str(cwe_raw), re.IGNORECASE)
                        cwe_clean = match.group(0).upper() if match else None
                        cve_item["cwe"] = cwe_clean

                        cves[(vendor_id, cve_id)] = (
                            vendor_id,
                            cve_id,
                            cwe_clean,
                            cve_item.get("description"),
                            cve_item.get("severity"),
                            cve_item.get("cvss_score"),
                            cve_item.get("cvss_vector"),
                            cve_item.get("initial_release_date"),
                            cve_item.get("latest_update_date"),
                            advisory_url
                        )

                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                    # --- Product Mapping ---
                    recommendations = "See advisory for patching details."
                    product_cpe_list = [
                        f"cpe:2.3:a:ibm:{p.get('product_name','*').lower().replace(' ','_')}:*"
                        for p in raw_data.get("products", [])
                    ]

                    for cve_item in raw_data.get("cves", []):
                        cve_id = cve_item.get("cve_id")
                        if not cve_id:
                            continue
                        cve_product_maps[(vendor_id, cve_id)] = (
                            vendor_id,
                            cve_id,
                            None,
                            recommendations
                        )

                # --- Bulk Inserts ---
                logger.info("Performing bulk inserts...")

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories
                        (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                        VALUES %s
                        ON CONFLICT (advisory_id)
                        DO UPDATE SET
                            title = EXCLUDED.title,
                            severity = EXCLUDED.severity,
                            advisory_url = EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves
                        (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector,
                         initial_release_date, latest_update_date, reference_url)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET
                            cwe_id = EXCLUDED.cwe_id,
                            description = EXCLUDED.description,
                            severity = EXCLUDED.severity,
                            cvss_score = EXCLUDED.cvss_score,
                            cvss_vector = EXCLUDED.cvss_vector,
                            initial_release_date = EXCLUDED.initial_release_date,
                            latest_update_date = EXCLUDED.latest_update_date,
                            reference_url = EXCLUDED.reference_url;
                    """, list(cves.values()))

                if cve_product_maps:
                    execute_values(cur, """
                        INSERT INTO cve_product_map
                        (vendor_id, cve_id, affected_products_cpe, recommendations)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET
                            affected_products_cpe = EXCLUDED.affected_products_cpe,
                            recommendations = EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))

                if advisory_cves_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id)
                        VALUES %s
                        ON CONFLICT DO NOTHING;
                    """, list(advisory_cves_map))

                # --- Mark Processed ---
                processed_ids = tuple(row[0] for row in rows)
                if processed_ids:
                    cur.execute(
                        "UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;",
                        (processed_ids,)
                    )

                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} {VENDOR_NAME} records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)


if __name__ == "__main__":
    main()
'''
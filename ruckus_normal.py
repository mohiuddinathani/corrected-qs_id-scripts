# ruckus_normal.py (Final Production Version)
import os
import json
import logging
import sys
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("ruckus_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Ruckus"


def parse_date(date_str):
    try:
        return datetime.strptime(date_str, "%B %d, %Y").date()
    except Exception:
        return None


def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Normalizer...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                # Ensure vendor exists
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name=%s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                # Fetch unprocessed records
                cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE vendor_name=%s AND processed=false;", (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info("No new Ruckus advisories to process.")
                    return

                advisories, cves, mappings, linkmap = {}, {}, {}, set()

                for sid, raw in tqdm(rows, desc="Processing Ruckus Advisories"):
                    data = raw if isinstance(raw, dict) else json.loads(raw)
                    adv_id = data.get("id")
                    if not adv_id: continue

                    title = data.get("title")
                    release = parse_date(data.get("release_date"))
                    update = parse_date(data.get("edit_date"))
                    url = data.get("link")
                    desc = data.get("description", "")
                    severity = "Unknown" 

                    # Advisory
                    advisories[adv_id] = (adv_id, vendor_id, title, None, release, update, url)

                    # CVEs
                    for cve_id in data.get("cves", []):
                        if not cve_id: continue
                        
                        cves[(vendor_id, cve_id)] = (
                            vendor_id,
                            cve_id,
                            None,  # cwe_id
                            desc,  # description
                            severity,
                            None, None,
                            None, None,
                            url
                        )
                        mappings[(vendor_id, cve_id)] = (vendor_id, cve_id, None, "See advisory URL.")
                        linkmap.add((adv_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")
                
                # --- SQL LOGIC: Living Database + Sequence Sync ---

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                        VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET
                            title = EXCLUDED.title,
                            latest_update_date = EXCLUDED.latest_update_date,
                            advisory_url = EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET
                            description = COALESCE(EXCLUDED.description, cves.description),
                            severity = COALESCE(EXCLUDED.severity, cves.severity),
                            reference_url = EXCLUDED.reference_url;
                    """, list(cves.values()))

                if mappings:
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
                        DO UPDATE SET recommendations = EXCLUDED.recommendations;
                    """, list(mappings.values()))

                if linkmap:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id)
                        VALUES %s
                        ON CONFLICT DO NOTHING;
                    """, list(linkmap))

                # Mark processed + Timestamp
                processed_ids = tuple(row[0] for row in rows)
                if processed_ids:
                    cur.execute("UPDATE vendor_staging_table SET processed = TRUE, processed_at = NOW() WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} Ruckus records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()

'''
# ruckus_normal.py (Production Version)
import os
import json
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
import logging
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("ruckus_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Ruckus"


def parse_date(date_str):
    try:
        return datetime.strptime(date_str, "%B %d, %Y").date()
    except Exception:
        return None


def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Normalizer...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn, conn.cursor() as cur:
            # Ensure vendor exists
            cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT DO NOTHING;", (VENDOR_NAME,))
            cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name=%s;", (VENDOR_NAME,))
            vendor_id = cur.fetchone()[0]

            # Fetch unprocessed records
            cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE vendor_name=%s AND processed=false;", (VENDOR_NAME,))
            rows = cur.fetchall()
            if not rows:
                logger.info("No new Ruckus advisories to process.")
                return

            advisories, cves, mappings, linkmap = {}, {}, {}, set()

            for sid, raw in tqdm(rows, desc="Processing Ruckus Advisories"):
                data = raw if isinstance(raw, dict) else json.loads(raw)
                adv_id = data.get("id")
                title = data.get("title")
                release = parse_date(data.get("release_date"))
                update = parse_date(data.get("edit_date"))
                url = data.get("link")
                desc = data.get("description", "")
                severity = "Unknown"

                # Advisory
                advisories[adv_id] = (adv_id, vendor_id, title, None, release, update, url)

                # CVEs
                for cve_id in data.get("cves", []):
                    cves[(vendor_id, cve_id)] = (
                        vendor_id,
                        cve_id,
                        None,  # cwe_id
                        None,  # description
                        None,
                        None, None,
                        None, None,
                        url
                    )
                    mappings[(vendor_id, cve_id)] = (vendor_id, cve_id, None, "See advisory URL.")
                    linkmap.add((adv_id, vendor_id, cve_id))

            logger.info("Performing bulk inserts...")
            if advisories:
                execute_values(cur, """
                    INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
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
                        description = EXCLUDED.description,
                        severity = EXCLUDED.severity,
                        latest_update_date = EXCLUDED.latest_update_date,
                        reference_url = EXCLUDED.reference_url;
                """, list(cves.values()))

            if mappings:
                execute_values(cur, """
                    INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations)
                    VALUES %s
                    ON CONFLICT (vendor_id, cve_id)
                    DO UPDATE SET recommendations = EXCLUDED.recommendations;
                """, list(mappings.values()))

            if linkmap:
                execute_values(cur, """
                    INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id)
                    VALUES %s
                    ON CONFLICT DO NOTHING;
                """, list(linkmap))

            # Mark processed
            cur.execute("UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;", (tuple([r[0] for r in rows]),))
            conn.commit()
            logger.info(f"✅ Normalization complete for {len(rows)} Ruckus records.")
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)


if __name__ == "__main__":
    main()
'''
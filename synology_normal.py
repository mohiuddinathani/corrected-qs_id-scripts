# Synology_normal.py (Final Production Version - Corrected)
import os
import re
import json
import logging
import psycopg2
import sys
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("synology_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Synology"

# --- Helper Functions ---
def clean_text(text):
    if not text:
        return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(date_str):
    if not date_str:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%B %d, %Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str.strip(), fmt).date()
        except (ValueError, TypeError):
            continue
    return None

def find_cves_in_text(text_blob):
    return sorted(list(set(re.findall(r"CVE-\d{4}-\d{4,7}", str(text_blob or ""), re.IGNORECASE))))

def parse_cve_details(text_blob):
    """Extracts severity, score, and vector details from text."""
    details = {"severity": None, "score": None, "vector": None}
    if not text_blob:
        return details

    target_string = str(text_blob)

    sev_match = re.search(r"(?:Impact|Severity):\s*([A-Za-z]+)", target_string, re.IGNORECASE)
    if sev_match:
        details["severity"] = sev_match.group(1).capitalize()

    score_match = re.search(r"Base Score:\s*([\d.]+)", target_string, re.IGNORECASE)
    if score_match:
        details["score"] = score_match.group(1)

    vector_match = re.search(r"(CVSS:3\.\d(?:/[\w:]+)+)", target_string, re.IGNORECASE)
    if vector_match:
        details["vector"] = vector_match.group(1)

    return details

# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Normalizer...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                # Ensure vendor exists
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                # Fetch raw staging data
                cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE vendor_name = %s AND processed = false;", (VENDOR_NAME,))
                rows = cur.fetchall()

                if not rows:
                    logger.info(f"No new {VENDOR_NAME} records to process.")
                    return

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    if not raw_data or not isinstance(raw_data, dict):
                        continue

                    title = clean_text(raw_data.get("title"))
                    publish_time = raw_data.get("publish_time")
                    advisory_date = parse_date(publish_time)
                    advisory_suffix = re.sub(r'\W+', '-', title or "unknown")[:30]  # safe slug
                    advisory_id = f"SYN-{advisory_date.year if advisory_date else 'NA'}-{advisory_suffix}"

                    if not advisory_id:
                        continue

                    # --- Advisory Record ---
                    advisories[advisory_id] = (
                        advisory_id,
                        vendor_id,
                        advisory_id,
                        raw_data.get("severity"),
                        parse_date(raw_data.get("publish_time")),
                        None,  # latest_update_date
                        raw_data.get("url"),
                    )

                    # --- CVE Records ---
                    cve_ids = find_cves_in_text(json.dumps(raw_data))
                    description_text = f"{raw_data.get('abstract', '')}\n{raw_data.get('detail', '')}".strip()
                    text_blob = f"{raw_data.get('detail', '')} {raw_data.get('severity', '')}"

                    for cve_id in cve_ids:
                        details = parse_cve_details(text_blob)
                        cve_key = (vendor_id, cve_id)

                        cves[cve_key] = (
                            vendor_id,
                            cve_id,
                            None,  # cwe_id (NULL)
                            clean_text(description_text),
                            details.get("severity"),
                            details.get("score"),
                            details.get("vector"),
                            None,  # initial_release_date (NULL)
                            None,  # latest_update_date (NULL)
                            raw_data.get("url"),
                        )

                        cve_product_maps[cve_key] = (vendor_id, cve_id, None, None)
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk database inserts...")

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (
                            advisory_id, vendor_id, title, severity,
                            initial_release_date, latest_update_date, advisory_url
                        )
                        VALUES %s
                        ON CONFLICT (advisory_id)
                        DO UPDATE SET
                            title = EXCLUDED.title,
                            severity = EXCLUDED.severity,
                            initial_release_date = EXCLUDED.initial_release_date;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (
                            vendor_id, cve_id, cwe_id, description,
                            severity, cvss_score, cvss_vector,
                            initial_release_date, latest_update_date, reference_url
                        )
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET
                            description = COALESCE(EXCLUDED.description, cves.description),
                            severity = COALESCE(EXCLUDED.severity, cves.severity),
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
                        INSERT INTO cve_product_map (
                            vendor_id, cve_id, affected_products_cpe, recommendations
                        )
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO NOTHING;
                    """, list(cve_product_maps.values()))

                if advisory_cves_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id)
                        VALUES %s
                        ON CONFLICT DO NOTHING;
                    """, list(advisory_cves_map))

                # Mark processed + Timestamp
                processed_ids = tuple(row[0] for row in rows)
                if processed_ids:
                    cur.execute("UPDATE vendor_staging_table SET processed = TRUE, processed_at = NOW() WHERE staging_id IN %s;", (processed_ids,))

                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} {VENDOR_NAME} records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()

'''
# Synology_normal.py (Production Version - Corrected)
import os
import re
import json
import logging
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("synology_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Synology"

# --- Helper Functions ---
def clean_text(text):
    if not text:
        return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(date_str):
    if not date_str:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%B %d, %Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str.strip(), fmt).date()
        except (ValueError, TypeError):
            continue
    return None

def find_cves_in_text(text_blob):
    return sorted(list(set(re.findall(r"CVE-\d{4}-\d{4,7}", str(text_blob or ""), re.IGNORECASE))))

def parse_cve_details(text_blob):
    """Extracts severity, score, and vector details from text."""
    details = {"severity": None, "score": None, "vector": None}
    if not text_blob:
        return details

    target_string = str(text_blob)

    sev_match = re.search(r"(?:Impact|Severity):\s*([A-Za-z]+)", target_string, re.IGNORECASE)
    if sev_match:
        details["severity"] = sev_match.group(1).capitalize()

    score_match = re.search(r"Base Score:\s*([\d.]+)", target_string, re.IGNORECASE)
    if score_match:
        details["score"] = score_match.group(1)

    vector_match = re.search(r"(CVSS:3\.\d(?:/[\w:]+)+)", target_string, re.IGNORECASE)
    if vector_match:
        details["vector"] = vector_match.group(1)

    return details

# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Normalizer...")
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

                # Fetch raw staging data
                cur.execute("""
                    SELECT staging_id, raw_data
                    FROM vendor_staging_table
                    WHERE vendor_name = %s AND processed = false;
                """, (VENDOR_NAME,))
                rows = cur.fetchall()

                if not rows:
                    logger.info(f"No new {VENDOR_NAME} records to process.")
                    return

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    if not raw_data or not isinstance(raw_data, dict):
                        continue

                    title = clean_text(raw_data.get("title"))
                    publish_time = raw_data.get("publish_time")
                    advisory_date = parse_date(publish_time)
                    advisory_suffix = re.sub(r'\W+', '-', title or "unknown")[:30]  # safe slug
                    advisory_id = f"SYN-{advisory_date.year if advisory_date else 'NA'}-{advisory_suffix}"

                    if not advisory_id:
                        continue

                    # --- Advisory Record ---
                    advisories[advisory_id] = (
                        advisory_id,
                        vendor_id,
                        advisory_id,
                        raw_data.get("severity"),
                        parse_date(raw_data.get("publish_time")),
                        None,  # latest_update_date
                        raw_data.get("url"),
                    )

                    # --- CVE Records ---
                    cve_ids = find_cves_in_text(json.dumps(raw_data))
                    description_text = f"{raw_data.get('abstract', '')}\n{raw_data.get('detail', '')}".strip()
                    text_blob = f"{raw_data.get('detail', '')} {raw_data.get('severity', '')}"

                    for cve_id in cve_ids:
                        details = parse_cve_details(text_blob)

                        cves[(vendor_id, cve_id)] = (
                            vendor_id,
                            cve_id,
                            None,  # cwe_id (NULL)
                            clean_text(description_text),
                            details.get("severity"),
                            details.get("score"),
                            details.get("vector"),
                            None,  # initial_release_date (NULL)
                            None,  # latest_update_date (NULL)
                            raw_data.get("url"),
                        )

                        cve_product_maps[(vendor_id, cve_id)] = (vendor_id, cve_id, None, None)
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (
                            advisory_id, vendor_id, title, severity,
                            initial_release_date, latest_update_date, advisory_url
                        )
                        VALUES %s
                        ON CONFLICT (advisory_id)
                        DO UPDATE SET
                            title = EXCLUDED.title,
                            severity = EXCLUDED.severity,
                            initial_release_date = EXCLUDED.initial_release_date;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (
                            vendor_id, cve_id, cwe_id, description,
                            severity, cvss_score, cvss_vector,
                            initial_release_date, latest_update_date, reference_url
                        )
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET
                            description = EXCLUDED.description,
                            reference_url = EXCLUDED.reference_url;
                    """, list(cves.values()))

                if cve_product_maps:
                    execute_values(cur, """
                        INSERT INTO cve_product_map (
                            vendor_id, cve_id, affected_products_cpe, recommendations
                        )
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
                    cur.execute("UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;", (processed_ids,))

                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} {VENDOR_NAME} records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()
'''
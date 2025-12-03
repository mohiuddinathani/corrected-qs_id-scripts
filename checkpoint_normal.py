# Checkpoint_normal.py (Final Production Version)
import os
import re
import logging
import json
import psycopg2
import sys
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("checkpoint_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Check_point"


# --- Helper Functions ---
def clean_text(text):
    if not text:
        return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()


def parse_date(date_str):
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00")).date()
    except (ValueError, TypeError):
        try:
            return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").date()
        except Exception:
            return None


def resolve_advisory_url(data):
    """Find advisory URL or build one from SK ID, skipping empty strings."""
    url = data.get("url")
    advisory_url = data.get("advisory_url")

    # prefer advisory_url if url is empty or None
    if advisory_url and (not url or url.strip() == ""):
        return advisory_url
    if url and url.strip() != "":
        return url

    # fallback: build from SK ID
    sk = data.get("skId") or data.get("skid") or data.get("sk")
    if sk:
        return f"https://support.checkpoint.com/results/sk/{sk}"
    return None


def extract_solution_text(solution_text):
    if not solution_text:
        return None
    match = re.split(r"\bNote\b", solution_text, flags=re.IGNORECASE)
    return match[0].strip() if match else solution_text.strip()


def format_recommendation(sk_id, solution_text):
    sk_link = f"https://support.checkpoint.com/results/sk/{sk_id}" if sk_id else None
    solution = extract_solution_text(solution_text)
    if sk_link and solution:
        return f"SK Link: {sk_link}\nSolution: {solution}"
    elif sk_link:
        return f"SK Link: {sk_link}"
    return solution


# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                # ensure vendor exists
                cur.execute("""
                    INSERT INTO vendors (vendor_name)
                    VALUES (%s)
                    ON CONFLICT (vendor_name) DO NOTHING;
                """, (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                # get unprocessed staging records
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
                    # parse JSON if stored as text
                    if isinstance(raw_data, str):
                        try:
                            raw_data = json.loads(raw_data)
                        except Exception:
                            logger.warning(f"Could not parse raw_data for staging_id={staging_id}")
                            continue

                    advisory_id = f"Checkpoint-{raw_data.get('id')}"
                    if not advisory_id:
                        continue

                    # ✅ Fix advisory URL selection
                    advisory_url = resolve_advisory_url(raw_data)
                    severity = raw_data.get("cpSeverity") or raw_data.get("severity")

                    advisories[advisory_id] = (
                        advisory_id,
                        vendor_id,
                        raw_data.get("solution_title") or raw_data.get("summary"),
                        severity,
                        parse_date(raw_data.get("published")),
                        parse_date(raw_data.get("updated")),
                        advisory_url
                    )

                    cve_id = raw_data.get("cveId")
                    if not cve_id:
                        continue

                    reference_url = (
                        raw_data.get("url") or
                        raw_data.get("advisory_url") or
                        advisory_url
                    )

                    cves[(vendor_id, cve_id)] = (
                        vendor_id,
                        cve_id,
                        None,
                        clean_text(raw_data.get("summary")),
                        None,
                        raw_data.get("cvss"),
                        raw_data.get("attackVector"),
                        None,
                        None,
                        None
                    )

                    recommendation = format_recommendation(raw_data.get("skId"), raw_data.get("Solution"))
                    cve_product_maps[(vendor_id, cve_id)] = (
                        vendor_id, cve_id, None, recommendation
                    )
                    advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                # --- Bulk Inserts ---
                logger.info("Performing bulk inserts...")
                
                # 1. ADVISORIES
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (
                            advisory_id, vendor_id, title, severity,
                            initial_release_date, latest_update_date, advisory_url
                        ) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE
                        SET title=EXCLUDED.title,
                            severity=EXCLUDED.severity,
                            advisory_url=EXCLUDED.advisory_url,
                            initial_release_date=EXCLUDED.initial_release_date,
                            latest_update_date=EXCLUDED.latest_update_date;
                    """, list(advisories.values()))

                # 2. CVEs
                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (
                            vendor_id, cve_id, cwe_id, description,
                            severity, cvss_score, cvss_vector,
                            initial_release_date, latest_update_date, reference_url
                        ) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE
                        SET description=EXCLUDED.description,
                            severity=EXCLUDED.severity,
                            cvss_score=EXCLUDED.cvss_score,
                            cvss_vector=EXCLUDED.cvss_vector,
                            reference_url=EXCLUDED.reference_url;
                    """, list(cves.values()))

                # 3. PRODUCT MAP (With Sequence Sync)
                if cve_product_maps:
                    # --- CRITICAL FIX: Sync the Sequence ---
                    cur.execute("""
                        SELECT setval('qs_id_seq', COALESCE((
                            SELECT MAX(SUBSTRING(qs_id FROM 4)::INTEGER) 
                            FROM cve_product_map
                        ), 0) + 1);
                    """)
                    
                    execute_values(cur, """
                        INSERT INTO cve_product_map (
                            vendor_id, cve_id, affected_products_cpe, recommendations
                        ) VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET 
                            recommendations=EXCLUDED.recommendations,
                            affected_products_cpe=EXCLUDED.affected_products_cpe;
                    """, list(cve_product_maps.values()))

                # 4. ADVISORY-CVE MAP
                if advisory_cves_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id)
                        VALUES %s ON CONFLICT DO NOTHING;
                    """, list(advisory_cves_map))

                # 5. MARK PROCESSED + TIMESTAMP
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
# Checkpoint_normal.py (Final Production Version)
import os
import re
import logging
import json
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("checkpoint_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Check_point"


# --- Helper Functions ---
def clean_text(text):
    if not text:
        return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()


def parse_date(date_str):
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00")).date()
    except (ValueError, TypeError):
        try:
            return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").date()
        except Exception:
            return None


def resolve_advisory_url(data):
    """Find advisory URL or build one from SK ID, skipping empty strings."""
    url = data.get("url")
    advisory_url = data.get("advisory_url")

    # prefer advisory_url if url is empty or None
    if advisory_url and (not url or url.strip() == ""):
        return advisory_url
    if url and url.strip() != "":
        return url

    # fallback: build from SK ID
    sk = data.get("skId") or data.get("skid") or data.get("sk")
    if sk:
        return f"https://support.checkpoint.com/results/sk/{sk}"
    return None


def extract_solution_text(solution_text):
    if not solution_text:
        return None
    match = re.split(r"\bNote\b", solution_text, flags=re.IGNORECASE)
    return match[0].strip() if match else solution_text.strip()


def format_recommendation(sk_id, solution_text):
    sk_link = f"https://support.checkpoint.com/results/sk/{sk_id}" if sk_id else None
    solution = extract_solution_text(solution_text)
    if sk_link and solution:
        return f"SK Link: {sk_link}\nSolution: {solution}"
    elif sk_link:
        return f"SK Link: {sk_link}"
    return solution


# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                # ensure vendor exists
                cur.execute("""
                    INSERT INTO vendors (vendor_name)
                    VALUES (%s)
                    ON CONFLICT (vendor_name) DO NOTHING;
                """, (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                # get unprocessed staging records
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
                    # parse JSON if stored as text
                    if isinstance(raw_data, str):
                        try:
                            raw_data = json.loads(raw_data)
                        except Exception:
                            logger.warning(f"Could not parse raw_data for staging_id={staging_id}")
                            continue

                    advisory_id = f"Checkpoint-{raw_data.get('id')}"
                    if not advisory_id:
                        continue

                    # ✅ Fix advisory URL selection
                    advisory_url = resolve_advisory_url(raw_data)
                    severity = raw_data.get("cpSeverity") or raw_data.get("severity")

                    advisories[advisory_id] = (
                        advisory_id,
                        vendor_id,
                        raw_data.get("solution_title") or raw_data.get("summary"),
                        severity,
                        parse_date(raw_data.get("published")),
                        parse_date(raw_data.get("updated")),
                        advisory_url
                    )

                    cve_id = raw_data.get("cveId")
                    if not cve_id:
                        continue

                    reference_url = (
                        raw_data.get("url") or
                        raw_data.get("advisory_url") or
                        advisory_url
                    )

                    cves[(vendor_id, cve_id)] = (
                        vendor_id,
                        cve_id,
                        None,
                        clean_text(raw_data.get("summary")),
                        None,
                        raw_data.get("cvss"),
                        raw_data.get("attackVector"),
                        None,
                        None,
                        None
                    )

                    recommendation = format_recommendation(raw_data.get("skId"), raw_data.get("Solution"))
                    cve_product_maps[(vendor_id, cve_id)] = (
                        vendor_id, cve_id, None, None
                    )
                    advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                # --- Bulk Inserts ---
                logger.info("Performing bulk inserts...")
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (
                            advisory_id, vendor_id, title, severity,
                            initial_release_date, latest_update_date, advisory_url
                        ) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE
                        SET title=EXCLUDED.title,
                            severity=EXCLUDED.severity,
                            advisory_url=EXCLUDED.advisory_url,
                            initial_release_date=EXCLUDED.initial_release_date,
                            latest_update_date=EXCLUDED.latest_update_date;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (
                            vendor_id, cve_id, cwe_id, description,
                            severity, cvss_score, cvss_vector,
                            initial_release_date, latest_update_date, reference_url
                        ) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE
                        SET description=EXCLUDED.description,
                            severity=EXCLUDED.severity,
                            cvss_score=EXCLUDED.cvss_score,
                            cvss_vector=EXCLUDED.cvss_vector,
                            reference_url=EXCLUDED.reference_url;
                    """, list(cves.values()))

                if cve_product_maps:
                    execute_values(cur, """
                        INSERT INTO cve_product_map (
                            vendor_id, cve_id, affected_products_cpe, recommendations
                        ) VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET recommendations=EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))

                if advisory_cves_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id)
                        VALUES %s ON CONFLICT DO NOTHING;
                    """, list(advisory_cves_map))

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
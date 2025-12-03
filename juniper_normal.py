# juniper_normal.py (Final Production Version - Final)
import psycopg2
import json
import re
import os
import sys
from datetime import datetime
from dotenv import load_dotenv
import logging
from tqdm import tqdm
from psycopg2.extras import execute_values

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)

load_dotenv()

# --- DB Config ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
}

VENDOR_NAME = "Juniper"

# --- Helpers ---
def parse_date(date_str):
    """Preserve old working date logic."""
    if not date_str or date_str in ["N/A", "-", ""]:
        return None
    try:
        return datetime.fromisoformat(date_str).date()
    except Exception:
        try:
            return datetime.strptime(date_str, "%Y-%m-%d").date()
        except Exception:
            return None


def parse_cvss(cvss_string):
    """
    Extracts CVSS v3.1 score and vector from Juniper's combined CVSS field.
    Ignores CVSS v4.0 data entirely.
    """
    if not cvss_string:
        return None, None

    # Normalize whitespace
    text = re.sub(r"\s+", " ", cvss_string.strip())

    # Try explicit CVSS v3.1 pattern first
    pattern_v31 = r"CVSS:\s*v?\s*3\.1\s*:\s*(\d+\.\d+)\s*\(\s*(CVSS:3\.1/[A-Za-z0-9:\/\-]+)\s*\)"
    match = re.search(pattern_v31, text, re.IGNORECASE)

    if match:
        score = float(match.group(1))
        vector = match.group(2)
        return score, vector

    # Fallback: handle simple score-vector if above fails
    score_match = re.search(r"v?\s*3\.1\s*:\s*(\d+\.\d+)", text)
    vector_match = re.search(r"(CVSS:3\.1/[A-Za-z0-9:\/\-]+)", text)
    score = float(score_match.group(1)) if score_match else None
    vector = vector_match.group(1) if vector_match else None

    return score, vector

# --- Main ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Normalization...")

    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:

                # Ensure vendor exists
                cur.execute("""
                    INSERT INTO vendors (vendor_name)
                    VALUES (%s)
                    ON CONFLICT (vendor_name) DO NOTHING;
                """, (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name=%s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                # Fetch unprocessed raw records
                cur.execute("""
                    SELECT staging_id, raw_data
                    FROM vendor_staging_table
                    WHERE vendor_name=%s AND processed=FALSE;
                """, (VENDOR_NAME,))
                rows = cur.fetchall()

                if not rows:
                    logger.info("✅ No new Juniper records to process.")
                    return

                advisories = []
                cves = []
                advisory_cve_map = []
                cve_product_map = []

                for staging_id, raw in tqdm(rows, desc="Normalizing Juniper Data"):

                    advisory_id = raw.get("advisory_id")
                    if not advisory_id:
                        continue

                    title = raw.get("title")
                    severity = raw.get("severity")
                    created = parse_date(raw.get("created"))
                    last_updated = parse_date(raw.get("last_updated"))
                    url = raw.get("url")

                    advisories.append((
                        advisory_id, vendor_id, title, severity, created, last_updated, url
                    ))

                    # Parse CVSS using old logic
                    cvss_score, cvss_vector = parse_cvss(raw.get("severity_assessment_score"))

                    # Parse CVEs
                    cve_ids = raw.get("cve_id")
                    if cve_ids:
                        valid_cves = re.findall(r"CVE-\d{4}-\d+", cve_ids)
                        for cve in valid_cves:
                            description = raw.get("problem")
                            reference = raw.get("related_information")
                            cwe_id = None
                            cve_severity = None

                            cves.append((
                                vendor_id, cve, cwe_id, description, cve_severity,
                                cvss_score, cvss_vector, None, None, reference
                            ))

                            advisory_cve_map.append((
                                advisory_id, vendor_id, cve
                            ))

                            # product_affected (old behavior)
                            product = None  # old logic used None for missing data
                            solution = raw.get("solution")
                            cve_product_map.append((
                                vendor_id, cve, None, solution
                            ))

                # Deduplicate CVEs before insert
                if cves:
                    unique_cves = {}
                    for record in cves:
                        key = (record[0], record[1])  # (vendor_id, cve_id)
                        unique_cves[key] = record
                    cves = list(unique_cves.values())

                # --- Bulk Inserts ---
                
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (
                            advisory_id, vendor_id, title, severity,
                            initial_release_date, latest_update_date, advisory_url
                        )
                        VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET
                            title=EXCLUDED.title,
                            severity=EXCLUDED.severity,
                            latest_update_date=EXCLUDED.latest_update_date,
                            advisory_url=EXCLUDED.advisory_url;
                    """, advisories)

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (
                            vendor_id, cve_id, cwe_id, description, severity, cvss_score,
                            cvss_vector, initial_release_date, latest_update_date, reference_url
                        )
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET
                            description = COALESCE(EXCLUDED.description, cves.description),
                            severity = COALESCE(EXCLUDED.severity, cves.severity),
                            cvss_score = COALESCE(EXCLUDED.cvss_score, cves.cvss_score),
                            cvss_vector = COALESCE(EXCLUDED.cvss_vector, cves.cvss_vector),
                            reference_url = EXCLUDED.reference_url;
                    """, cves)

                if cve_product_map:
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
                            affected_products_cpe = EXCLUDED.affected_products_cpe,
                            recommendations = EXCLUDED.recommendations;
                    """, cve_product_map)

                if advisory_cve_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id)
                        VALUES %s
                        ON CONFLICT DO NOTHING;
                    """, advisory_cve_map)

                # --- Mark Processed + Timestamp ---
                processed_ids = tuple(row[0] for row in rows)
                if processed_ids:
                    cur.execute("""
                        UPDATE vendor_staging_table
                        SET processed=TRUE, processed_at=NOW()
                        WHERE staging_id IN %s;
                    """, (processed_ids,))
                    
                conn.commit()
                logger.info(f"✅ Normalization completed successfully for {len(rows)} Juniper records.")

    except Exception as e:
        logger.error(f"❌ Error during normalization: {e}", exc_info=True)

if __name__ == "__main__":
    main()


'''
# juniper_normal.py (Final Production Version – Old Logic Preserved)
import psycopg2
import json
import re
import os
from datetime import datetime
from dotenv import load_dotenv
import logging
from tqdm import tqdm
from psycopg2.extras import execute_values

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

load_dotenv()

# --- DB Config ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
}

VENDOR_NAME = "Juniper"

# --- Helpers ---
def parse_date(date_str):
    """Preserve old working date logic."""
    if not date_str or date_str in ["N/A", "-", ""]:
        return None
    try:
        return datetime.fromisoformat(date_str).date()
    except Exception:
        try:
            return datetime.strptime(date_str, "%Y-%m-%d").date()
        except Exception:
            return None


def parse_cvss(cvss_string):
    """
    Extracts CVSS v3.1 score and vector from Juniper's combined CVSS field.
    Ignores CVSS v4.0 data entirely.
    """
    if not cvss_string:
        return None, None

    # Normalize whitespace
    text = re.sub(r"\s+", " ", cvss_string.strip())

    # Try explicit CVSS v3.1 pattern first
    pattern_v31 = r"CVSS:\s*v?\s*3\.1\s*:\s*(\d+\.\d+)\s*\(\s*(CVSS:3\.1/[A-Za-z0-9:\/\-]+)\s*\)"
    match = re.search(pattern_v31, text, re.IGNORECASE)

    if match:
        score = float(match.group(1))
        vector = match.group(2)
        return score, vector

    # Fallback: handle simple score-vector if above fails
    score_match = re.search(r"v?\s*3\.1\s*:\s*(\d+\.\d+)", text)
    vector_match = re.search(r"(CVSS:3\.1/[A-Za-z0-9:\/\-]+)", text)
    score = float(score_match.group(1)) if score_match else None
    vector = vector_match.group(1) if vector_match else None

    return score, vector




# --- Main ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Normalization with old extraction logic...")

    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:

                # Ensure vendor exists
                cur.execute("""
                    INSERT INTO vendors (vendor_name)
                    VALUES (%s)
                    ON CONFLICT (vendor_name) DO NOTHING;
                """, (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name=%s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                # Fetch unprocessed raw records
                cur.execute("""
                    SELECT staging_id, raw_data
                    FROM vendor_staging_table
                    WHERE vendor_name=%s AND processed=FALSE;
                """, (VENDOR_NAME,))
                rows = cur.fetchall()

                if not rows:
                    logger.info("✅ No new Juniper records to process.")
                    return

                advisories = []
                cves = []
                advisory_cve_map = []
                cve_product_map = []

                for staging_id, raw in tqdm(rows, desc="Normalizing Juniper Data"):

                    advisory_id = raw.get("advisory_id")
                    if not advisory_id:
                        continue

                    title = raw.get("title")
                    severity = raw.get("severity")
                    created = parse_date(raw.get("created"))
                    last_updated = parse_date(raw.get("last_updated"))
                    url = raw.get("url")

                    advisories.append((
                        advisory_id, vendor_id, title, severity, created, last_updated, url
                    ))

                    # Parse CVSS using old logic
                    cvss_score, cvss_vector = parse_cvss(raw.get("severity_assessment_score"))

                    # Parse CVEs
                    cve_ids = raw.get("cve_id")
                    if cve_ids:
                        valid_cves = re.findall(r"CVE-\d{4}-\d+", cve_ids)
                        for cve in valid_cves:
                            description = raw.get("problem")
                            reference = raw.get("related_information")
                            cwe_id = None
                            cve_severity = None

                            cves.append((
                                vendor_id, cve, cwe_id, description, cve_severity,
                                cvss_score, cvss_vector, None, None, reference
                            ))


                            advisory_cve_map.append((
                                advisory_id, cve
                            ))

                            # product_affected (old behavior)
                            product = None  # old logic used None for missing data
                            solution = raw.get("solution")
                            cve_product_map.append((
                                cve, None, solution
                            ))

                    # Mark raw as processed
                    cur.execute("""
                        UPDATE vendor_staging_table
                        SET processed=TRUE
                        WHERE staging_id=%s;
                    """, (staging_id,))
                    
                if cves:
                    unique_cves = {}
                    for record in cves:
                        key = (record[0], record[1])  # (vendor_id, cve_id)
                        unique_cves[key] = record
                    cves = list(unique_cves.values())

                # --- Bulk Inserts (optimized, but logic unchanged) ---
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (
                            advisory_id, vendor_id, title, severity,
                            initial_release_date, latest_update_date, advisory_url
                        )
                        VALUES %s
                        ON CONFLICT (advisory_id) DO NOTHING;
                    """, advisories)

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (
                            vendor_id, cve_id, cwe_id, description, severity, cvss_score,
                            cvss_vector, initial_release_date, latest_update_date, reference_url
                        )
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
                    """, cves)




                if advisory_cve_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id)
                        VALUES %s
                        ON CONFLICT DO NOTHING;
                    """, [(advisory_id, vendor_id, cve_id) for advisory_id, cve_id in advisory_cve_map])
                

                if cve_product_map:
                    execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO NOTHING;
                    """, [(vendor_id, cve, product, solution) for cve, product, solution in cve_product_map])


                conn.commit()
                logger.info(f"✅ Normalization completed successfully for {len(rows)} Juniper records.")

    except Exception as e:
        logger.error(f"❌ Error during normalization: {e}", exc_info=True)


if __name__ == "__main__":
    main()
'''
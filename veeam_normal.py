# veeam_normal.py (Final Production Version)
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
logger = logging.getLogger("veeam_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Veeam"

# --- Helper Functions ---
def clean_text(text):
    if not text:
        return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(date_string):
    if not date_string or not isinstance(date_string, str):
        return None
    for fmt in ("%B %d, %Y", "%b %d, %Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_string.strip(), fmt).date()
        except (ValueError, TypeError):
            continue
    return None

def calculate_severity(score):
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"

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

                # Fetch unprocessed raw data
                cur.execute(
                    "SELECT staging_id, raw_data FROM vendor_staging_table WHERE vendor_name=%s AND processed=false",
                    (VENDOR_NAME,),
                )
                rows = cur.fetchall()
                if not rows:
                    logger.info(f"No new {VENDOR_NAME} records to process.")
                    return

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    advisory_id = f"KB{raw_data.get('kb_id')}" if raw_data.get("kb_id") else raw_data.get("link")
                    if not advisory_id:
                        continue

                    vulnerabilities = raw_data.get("vulnerabilities", [])
                    severities = [
                        vuln.get("severity", "").capitalize()
                        for vuln in vulnerabilities
                        if vuln.get("severity")
                    ]
                    highest_severity = (
                        max(severities, key=lambda s: {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(s, 0))
                        if severities
                        else "Unknown"
                    )

                    # 1. Advisory Record
                    advisories[advisory_id] = (
                        advisory_id,
                        vendor_id,
                        raw_data.get("title"),
                        highest_severity,
                        parse_date(raw_data.get("published")),
                        parse_date(raw_data.get("last_modified")),
                        raw_data.get("link"),
                    )

                    # --- CASE 1: advisory has vulnerabilities ---
                    if vulnerabilities:
                        for vuln in vulnerabilities:
                            cve_id = vuln.get("cve_id")
                            if not cve_id or cve_id == "N/A":
                                cve_id = f"NOCVE-{advisory_id}"
                            else:
                                cve_id = cve_id.strip().upper()

                            description = clean_text(vuln.get("description")) or "See advisory."

                            cvss_score = None
                            try:
                                if vuln.get("cvss_score") is not None:
                                    cvss_score = float(vuln.get("cvss_score"))
                            except (ValueError, TypeError):
                                cvss_score = None

                            vuln_sev = vuln.get("severity")
                            if isinstance(vuln_sev, str) and vuln_sev.strip():
                                severity_value = vuln_sev.strip().capitalize()
                            else:
                                severity_value = calculate_severity(cvss_score)

                            # 2. CVE Record
                            cve_key = (vendor_id, cve_id)
                            cves[cve_key] = (
                                vendor_id,
                                cve_id,
                                None, # CWE
                                description,
                                severity_value,
                                cvss_score,
                                vuln.get("cvss_vector"),
                                parse_date(raw_data.get("published")),
                                parse_date(raw_data.get("last_modified")),
                                raw_data.get("link"),
                            )

                            # 3. Product Map
                            cve_product_maps[cve_key] = (
                                vendor_id,
                                cve_id,
                                None,
                                "See advisory URL for patching details.",
                            )
                            
                            # 4. Map
                            advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                    # --- CASE 2: advisory has NO vulnerabilities ---
                    else:
                        cve_id = f"NOCVE-{advisory_id}"
                        cve_key = (vendor_id, cve_id)
                        
                        cves[cve_key] = (
                            vendor_id,
                            cve_id,
                            None,
                            clean_text(raw_data.get("description")) or "No CVE details available; refer advisory.",
                            highest_severity,
                            None,
                            None,
                            parse_date(raw_data.get("published")),
                            parse_date(raw_data.get("last_modified")),
                            raw_data.get("link"),
                        )
                        cve_product_maps[cve_key] = (
                            vendor_id,
                            cve_id,
                            None,
                            "See advisory URL for patching details.",
                        )
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk database inserts...")
                
                # --- SQL LOGIC: Living Database + Sequence Sync ---

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                        VALUES %s
                        ON CONFLICT (advisory_id)
                        DO UPDATE SET
                            title = EXCLUDED.title,
                            severity = EXCLUDED.severity,
                            latest_update_date = EXCLUDED.latest_update_date,
                            advisory_url = EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector,
                                          initial_release_date, latest_update_date, reference_url)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET
                            description = COALESCE(EXCLUDED.description, cves.description),
                            severity = COALESCE(EXCLUDED.severity, cves.severity),
                            cvss_score = COALESCE(EXCLUDED.cvss_score, cves.cvss_score),
                            cvss_vector = COALESCE(EXCLUDED.cvss_vector, cves.cvss_vector),
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
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET
                            recommendations = EXCLUDED.recommendations;
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
# veeam_normal.py (Production Version) — 1 advisory = 1 CVE (fallback if missing)
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
logger = logging.getLogger("veeam_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Veeam"

# --- Helper Functions ---
def clean_text(text):
    if not text:
        return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(date_string):
    if not date_string or not isinstance(date_string, str):
        return None
    for fmt in ("%B %d, %Y", "%b %d, %Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_string.strip(), fmt).date()
        except (ValueError, TypeError):
            continue
    return None

def calculate_severity(score):
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"

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

                # Fetch unprocessed raw data
                cur.execute(
                    "SELECT staging_id, raw_data FROM vendor_staging_table WHERE vendor_name=%s AND processed=false",
                    (VENDOR_NAME,),
                )
                rows = cur.fetchall()
                if not rows:
                    logger.info(f"No new {VENDOR_NAME} records to process.")
                    return

                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    advisory_id = f"KB{raw_data.get('kb_id')}" if raw_data.get("kb_id") else raw_data.get("link")
                    if not advisory_id:
                        continue

                    vulnerabilities = raw_data.get("vulnerabilities", [])
                    severities = [
                        vuln.get("severity", "").capitalize()
                        for vuln in vulnerabilities
                        if vuln.get("severity")
                    ]
                    highest_severity = (
                        max(severities, key=lambda s: {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(s, 0))
                        if severities
                        else "Unknown"
                    )

                    advisories[advisory_id] = (
                        advisory_id,
                        vendor_id,
                        raw_data.get("title"),
                        highest_severity,
                        parse_date(raw_data.get("published")),
                        parse_date(raw_data.get("last_modified")),
                        raw_data.get("link"),
                    )

                    # --- CASE 1: advisory has vulnerabilities ---
                    if vulnerabilities:
                        for vuln in vulnerabilities:
                            cve_id = vuln.get("cve_id")
                            if not cve_id or cve_id == "N/A":
                                cve_id = f"NOCVE-{advisory_id}"
                            else:
                                cve_id = cve_id.strip().upper()

                            description = clean_text(vuln.get("description")) or "See advisory."

                            cvss_score = None
                            try:
                                if vuln.get("cvss_score") is not None:
                                    cvss_score = float(vuln.get("cvss_score"))
                            except (ValueError, TypeError):
                                cvss_score = None

                            vuln_sev = vuln.get("severity")
                            if isinstance(vuln_sev, str) and vuln_sev.strip():
                                severity_value = vuln_sev.strip().capitalize()
                            else:
                                severity_value = calculate_severity(cvss_score)

                            cves[(vendor_id, cve_id)] = (
                                vendor_id,
                                cve_id,
                                None,
                                description,
                                severity_value,
                                cvss_score,
                                vuln.get("cvss_vector"),
                                parse_date(raw_data.get("published")),
                                parse_date(raw_data.get("last_modified")),
                                raw_data.get("link"),
                            )

                            cve_product_maps[(vendor_id, cve_id)] = (
                                vendor_id,
                                cve_id,
                                None,
                                "See advisory URL for patching details.",
                            )
                            advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                    # --- CASE 2: advisory has NO vulnerabilities ---
                    else:
                        cve_id = f"NOCVE-{advisory_id}"
                        cves[(vendor_id, cve_id)] = (
                            vendor_id,
                            cve_id,
                            None,
                            clean_text(raw_data.get("description")) or "No CVE details available; refer advisory.",
                            highest_severity,
                            None,
                            None,
                            parse_date(raw_data.get("published")),
                            parse_date(raw_data.get("last_modified")),
                            raw_data.get("link"),
                        )
                        cve_product_maps[(vendor_id, cve_id)] = (
                            vendor_id,
                            cve_id,
                            None,
                            "See advisory URL for patching details.",
                        )
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info(
                    f"Prepared rows => advisories: {len(advisories)}, cves: {len(cves)}, cve_product_maps: {len(cve_product_maps)}, advisory_cves_map: {len(advisory_cves_map)}"
                )

                # --- Bulk Inserts ---
                logger.info("Performing bulk inserts...")
                if advisories:
                    execute_values(
                        cur,
                        """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                        VALUES %s
                        ON CONFLICT (advisory_id)
                        DO UPDATE SET
                            title=EXCLUDED.title,
                            severity=EXCLUDED.severity,
                            latest_update_date=EXCLUDED.latest_update_date;
                        """,
                        list(advisories.values()),
                    )

                if cves:
                    execute_values(
                        cur,
                        """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector,
                                          initial_release_date, latest_update_date, reference_url)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET
                            description = EXCLUDED.description,
                            severity = EXCLUDED.severity,
                            cvss_score = EXCLUDED.cvss_score,
                            cvss_vector = EXCLUDED.cvss_vector,
                            reference_url = EXCLUDED.reference_url;
                        """,
                        list(cves.values()),
                    )

                if cve_product_maps:
                    execute_values(
                        cur,
                        """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id)
                        DO UPDATE SET
                            affected_products_cpe = EXCLUDED.affected_products_cpe,
                            recommendations = EXCLUDED.recommendations;
                        """,
                        list(cve_product_maps.values()),
                    )

                if advisory_cves_map:
                    execute_values(
                        cur,
                        """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id)
                        VALUES %s
                        ON CONFLICT (advisory_id, vendor_id, cve_id)
                        DO NOTHING;
                        """,
                        list(advisory_cves_map),
                    )

                processed_ids = tuple(row[0] for row in rows)
                if processed_ids:
                    cur.execute(
                        "UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;",
                        (processed_ids,),
                    )

                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} {VENDOR_NAME} records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)


if __name__ == "__main__":
    main()
'''
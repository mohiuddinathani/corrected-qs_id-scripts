# postgresql_normalizer.py (Final — CVSS Logic Fixed)
import logging, re, os, sys, math, datetime
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import execute_values, Json
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), 
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), 
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
}
VENDOR_NAME = "PostgreSQL"

# --- Helper Functions ---
def calculate_cvss_from_vector(vector_string: str) -> dict:
    """Accurately calculates CVSS v3.x base score and severity from vector string."""
    if not vector_string:
        return {"base_score": None, "severity": "Unknown"}

    try:
        vector_string = vector_string.strip()
        if vector_string.startswith("CVSS:3.1/"):
            vector_string = vector_string.replace("CVSS:3.1/", "")
        elif vector_string.startswith("CVSS:3.0/"):
            vector_string = vector_string.replace("CVSS:3.0/", "")

        metrics = dict(p.split(":", 1) for p in vector_string.split("/") if ":" in p)

        AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        AC = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
              "C": {"N": 0.85, "L": 0.68, "H": 0.50}}[metrics["S"]][metrics["PR"]]
        UI = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        C = {"N": 0.0, "L": 0.22, "H": 0.56}[metrics["C"]]
        I = {"N": 0.0, "L": 0.22, "H": 0.56}[metrics["I"]]
        A = {"N": 0.0, "L": 0.22, "H": 0.56}[metrics["A"]]

        exploitability = 8.22 * AV * AC * PR * UI
        iss = 1 - ((1 - C) * (1 - I) * (1 - A))
        
        if metrics["S"] == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        if impact <= 0:
            base_score = 0.0
        else:
            if metrics["S"] == "U":
                base_score = round(min(impact + exploitability, 10), 1)
            else:
                base_score = round(min(1.08 * (impact + exploitability), 10), 1)

        if base_score == 0.0:
            severity = "None"
        elif base_score <= 3.9:
            severity = "Low"
        elif base_score <= 6.9:
            severity = "Medium"
        elif base_score <= 8.9:
            severity = "High"
        else:
            severity = "Critical"

        return {"base_score": base_score, "severity": severity}

    except Exception as e:
        return {"base_score": None, "severity": "Unknown"}

def _parse_iso_or_none(s):
    if not s: return None
    try: return datetime.datetime.fromisoformat(s).date()
    except Exception:
        for fmt in ("%Y-%m-%d", "%b %d, %Y", "%B %d, %Y", "%d %B %Y"):
            try: return datetime.datetime.strptime(s, fmt).date()
            except Exception: continue
    return None

def _get_dates_from_versions(version_information):
    dates = []
    for v in version_information or []:
        fp = v.get("fix_published")
        if not fp: continue
        d = _parse_iso_or_none(fp)
        if d: dates.append(d)
    if not dates: return None, None
    return min(dates), max(dates)

# --- Main Processing ---
def main():
    logger.info(f"🚀 Starting Final {VENDOR_NAME} Processor...")

    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                # Ensure Vendor Exists
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                # Fetch Staging Data
                cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE vendor_name = %s AND processed = FALSE;", (VENDOR_NAME,))
                rows = cur.fetchall()

                if not rows:
                    logger.info("No new PostgreSQL records to process.")
                    return

                advisories, cves, advisory_cve_map, cve_product_map = [], [], [], []
                processed_ids, year_counter = [], {}

                for staging_id, raw in tqdm(rows, desc="Parsing Staged Data"):
                    processed_ids.append(staging_id)
                    cve_id = raw.get("cve_id")
                    if not cve_id or "CVE-" not in cve_id:
                        continue

                    try:
                        year = int(cve_id.split('-')[1])
                    except Exception:
                        year = datetime.datetime.now().year
                    
                    year_counter[year] = year_counter.get(year, 0) + 1
                    advisory_id = f"PG-CVE-{year}-{year_counter[year]:03d}"

                    initial_date, latest_date = _get_dates_from_versions(raw.get("version_information", []))
                    if not initial_date and raw.get("published_date"):
                        initial_date = _parse_iso_or_none(raw.get("published_date"))
                    if not latest_date and raw.get("published_date"):
                        latest_date = _parse_iso_or_none(raw.get("published_date"))

                    # CWE
                    cwe_id = None
                    raw_cwe = raw.get("cwe_id") or raw.get("cwe")
                    if raw_cwe:
                        m = re.search(r"(CWE-\d+)", str(raw_cwe), re.IGNORECASE)
                        if m: cwe_id = m.group(1).upper()

                    # CVSS
                    cvss_block = raw.get("cvss_v3", {}) or {}
                    vector = (
                        cvss_block.get("vector") or cvss_block.get("vector_string") or 
                        cvss_block.get("vectorString") or cvss_block.get("base_vector") or 
                        cvss_block.get("vector_str") or cvss_block.get("cvss_vector") or 
                        raw.get("cvss_vector") or raw.get("vector")
                    )
                    score_info = calculate_cvss_from_vector(vector) if vector else {"base_score": None, "severity": None}
                    
                    if not score_info["base_score"] and raw.get("cvss_v3", {}).get("overall_score"):
                        try:
                            score_info["base_score"] = float(raw["cvss_v3"]["overall_score"])
                        except ValueError: pass

                    # 1. Advisory
                    advisories.append((
                        advisory_id, vendor_id, raw.get("title"), 
                        score_info.get("severity") or raw.get("severity"),
                        None, None, raw.get("url")
                    ))

                    # 2. CVE
                    cves.append((
                        vendor_id, cve_id, cwe_id, raw.get("description"),
                        score_info.get("severity"), score_info.get("base_score"),
                        vector, None, None, raw.get("url")
                    ))

                    advisory_cve_map.append((advisory_id, vendor_id, cve_id))

                    # 3. Product Map
                    recommendations = [f"Upgrade to {v.get('fixed_in')}" for v in raw.get("version_information", []) if v.get("fixed_in")]
                    rec_text = "; ".join(recommendations) if recommendations else "See advisory for details."
                    cve_product_map.append((vendor_id, cve_id, None, rec_text))

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
                    """, advisories)

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        cwe_id=COALESCE(EXCLUDED.cwe_id, cves.cwe_id), 
                        description=COALESCE(EXCLUDED.description, cves.description), 
                        severity=COALESCE(EXCLUDED.severity, cves.severity), 
                        cvss_score=COALESCE(EXCLUDED.cvss_score, cves.cvss_score), 
                        cvss_vector=COALESCE(EXCLUDED.cvss_vector, cves.cvss_vector),
                        latest_update_date=EXCLUDED.latest_update_date,
                        reference_url=EXCLUDED.reference_url;
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
                        recommendations=EXCLUDED.recommendations,
                        affected_products_cpe=EXCLUDED.affected_products_cpe;
                    """, cve_product_map)

                if advisory_cve_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) 
                        VALUES %s ON CONFLICT DO NOTHING;
                    """, advisory_cve_map)

                if processed_ids:
                    cur.execute("""
                        UPDATE vendor_staging_table SET processed = TRUE, processed_at = NOW() 
                        WHERE staging_id IN %s;
                    """, (tuple(processed_ids),))

                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} staged records.")

    except Exception as e:
        logger.error(f"❌ Error during normalization: {e}", exc_info=True)

if __name__ == "__main__":
    main()




'''
# postgresql_normalizer.py (Final — CVSS Logic Fixed)
import logging, re, os, sys, math, datetime
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import execute_values, Json
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), 
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), 
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
}
VENDOR_NAME = "PostgreSQL"

# --- Helper Functions ---
def calculate_cvss_from_vector(vector_string: str) -> dict:
    """Accurately calculates CVSS v3.x base score and severity from vector string."""
    if not vector_string:
        return {"base_score": None, "severity": "Unknown"}

    try:
        # Remove prefixes like "CVSS:3.1/" or "CVSS:3.0/"
        vector_string = vector_string.strip()
        if vector_string.startswith("CVSS:3.1/"):
            vector_string = vector_string.replace("CVSS:3.1/", "")
        elif vector_string.startswith("CVSS:3.0/"):
            vector_string = vector_string.replace("CVSS:3.0/", "")

        # Parse metrics
        metrics = dict(p.split(":", 1) for p in vector_string.split("/") if ":" in p)

        # --- CVSS v3.1 weights ---
        AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        AC = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
              "C": {"N": 0.85, "L": 0.68, "H": 0.50}}[metrics["S"]][metrics["PR"]]
        UI = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        C = {"N": 0.0, "L": 0.22, "H": 0.56}[metrics["C"]]
        I = {"N": 0.0, "L": 0.22, "H": 0.56}[metrics["I"]]
        A = {"N": 0.0, "L": 0.22, "H": 0.56}[metrics["A"]]

        # --- Exploitability Sub-Score ---
        exploitability = 8.22 * AV * AC * PR * UI

        # --- Impact Sub-Score ---
        iss = 1 - ((1 - C) * (1 - I) * (1 - A))
        if metrics["S"] == "U":
            impact = 6.42 * iss
        else:  # S = C
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # --- Base Score ---
        if impact <= 0:
            base_score = 0.0
        else:
            if metrics["S"] == "U":
                base_score = round(min(impact + exploitability, 10), 1)
            else:
                base_score = round(min(1.08 * (impact + exploitability), 10), 1)

        # --- Severity ---
        if base_score == 0.0:
            severity = "None"
        elif base_score <= 3.9:
            severity = "Low"
        elif base_score <= 6.9:
            severity = "Medium"
        elif base_score <= 8.9:
            severity = "High"
        else:
            severity = "Critical"

        return {"base_score": base_score, "severity": severity}

    except Exception as e:
        logger.error(f"CVSS parse error for vector '{vector_string}': {e}")
        return {"base_score": None, "severity": "Unknown"}




def _parse_iso_or_none(s):
    """Return date object from iso string or None."""
    if not s:
        return None
    try:
        return datetime.datetime.fromisoformat(s).date()
    except Exception:
        for fmt in ("%Y-%m-%d", "%b %d, %Y", "%B %d, %Y", "%d %B %Y"):
            try:
                return datetime.datetime.strptime(s, fmt).date()
            except Exception:
                continue
    return None


def _get_dates_from_versions(version_information):
    """Extract min/max fix_published dates."""
    dates = []
    for v in version_information or []:
        fp = v.get("fix_published")
        if not fp:
            continue
        d = _parse_iso_or_none(fp)
        if d:
            dates.append(d)
    if not dates:
        return None, None
    return min(dates), max(dates)


# --- Main Processing ---
def main():
    logger.info(f"🚀 Starting Final {VENDOR_NAME} Processor...")

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
                    WHERE vendor_name = %s AND processed = FALSE;
                """, (VENDOR_NAME,))
                rows = cur.fetchall()

                if not rows:
                    logger.info("No new PostgreSQL records to process.")
                    return

                advisories, cves, advisory_cve_map, cve_product_map = [], [], [], []
                processed_ids, year_counter = [], {}

                for staging_id, raw in tqdm(rows, desc="Parsing Staged Data"):
                    processed_ids.append(staging_id)
                    cve_id = raw.get("cve_id")
                    if not cve_id or "CVE-" not in cve_id:
                        continue

                    try:
                        year = int(cve_id.split('-')[1])
                    except Exception:
                        year = datetime.datetime.now().year
                    year_counter[year] = year_counter.get(year, 0) + 1
                    advisory_id = f"PG-CVE-{year}-{year_counter[year]:03d}"

                    # Dates
                    initial_date, latest_date = _get_dates_from_versions(raw.get("version_information", []))
                    if not initial_date and raw.get("published_date"):
                        initial_date = _parse_iso_or_none(raw.get("published_date"))
                    if not latest_date and raw.get("published_date"):
                        latest_date = _parse_iso_or_none(raw.get("published_date"))

                    # CWE
                    cwe_id = None
                    raw_cwe = raw.get("cwe_id") or raw.get("cwe")
                    if raw_cwe:
                        m = re.search(r"(CWE-\d+)", str(raw_cwe), re.IGNORECASE)
                        if m:
                            cwe_id = m.group(1).upper()

                    # CVSS vector & score
                    cvss_block = raw.get("cvss_v3", {}) or {}
                    vector = (
                        cvss_block.get("vector")
                        or cvss_block.get("vector_string")
                        or cvss_block.get("vectorString")
                        or cvss_block.get("base_vector")
                        or cvss_block.get("vector_str")
                        or cvss_block.get("cvss_vector")
                        or raw.get("cvss_vector")
                        or raw.get("vector")
                    )
                    score_info = calculate_cvss_from_vector(vector) if vector else {"base_score": None, "severity": None}
                    
                    # After calculating score_info:
                    if not score_info["base_score"] and raw.get("cvss_v3", {}).get("overall_score"):
                        try:
                            score_info["base_score"] = float(raw["cvss_v3"]["overall_score"])
                        except ValueError:
                            pass


                    advisories.append((
                        advisory_id, vendor_id, raw.get("title"), 
                        score_info.get("severity") or raw.get("severity"),
                        None, None, raw.get("url")
                    ))

                    cves.append((
                        vendor_id, cve_id, cwe_id, raw.get("description"),
                        score_info.get("severity"), score_info.get("base_score"),
                        vector, None, None, raw.get("url")
                    ))

                    advisory_cve_map.append((advisory_id, vendor_id, cve_id))

                    recommendations = [f"Upgrade to {v.get('fixed_in')}" for v in raw.get("version_information", []) if v.get("fixed_in")]
                    rec_text = "; ".join(recommendations) if recommendations else "See advisory for details."
                    cve_product_map.append((vendor_id, cve_id, None, rec_text))

                logger.info("Performing bulk inserts...")

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, 
                                                initial_release_date, latest_update_date, advisory_url)
                        VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE 
                        SET title = EXCLUDED.title, severity = EXCLUDED.severity, 
                            latest_update_date = EXCLUDED.latest_update_date;
                    """, advisories)

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, 
                                          cvss_score, cvss_vector, initial_release_date, 
                                          latest_update_date, reference_url)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE
                        SET description = COALESCE(EXCLUDED.description, cves.description),
                            severity = COALESCE(EXCLUDED.severity, cves.severity),
                            latest_update_date = EXCLUDED.latest_update_date;
                    """, cves)

                if advisory_cve_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id)
                        VALUES %s
                        ON CONFLICT DO NOTHING;
                    """, advisory_cve_map)

                if cve_product_map:
                    execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations)
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE 
                        SET recommendations = EXCLUDED.recommendations;
                    """, cve_product_map)

                if processed_ids:
                    cur.execute(
                        "UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;",
                        (tuple(processed_ids),)
                    )

                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} staged records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)


if __name__ == "__main__":
    main()
'''
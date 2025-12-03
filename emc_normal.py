# Dell_normal.py (Final Production Version)
import os
import re
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
logger = logging.getLogger("dell_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Dell EMC"

# --- Helper Functions ---
def clean_text(text):
    if not text: return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()

def parse_date(date_str):
    if not date_str:
        return None
    for fmt in ("%b %d %Y", "%d %b %Y", "%d %B %Y"):
        try:
            return datetime.strptime(str(date_str).strip(), fmt).date()
        except:
            continue
    return None

def safe_numeric(value):
    if not value: return None
    match = re.search(r"(\d+\.\d+|\d+)", str(value))
    if match:
        try: return float(match.group(1))
        except (ValueError, TypeError): return None
    return None

CVE_HEADER_NAMES = ["Proprietary Code CVEs", "Proprietary Code CVE"]

def clean_description(desc):
    if not desc or len(desc.strip()) <= 20:
        return None
    return desc.strip()

def clean_vector(vector):
    if not vector:
        return None
    # Remove NVD reference text (flexible for http/https and spacing)
    vector = re.sub(
        r"See NVD\s*\(https?://nvd\.nist\.gov[^\)]*\)\s*for\s*individual scores for each CVE\.?",
        "",
        vector,
        flags=re.IGNORECASE
    )
    vector = vector.strip()
    return vector if vector.lower().startswith(("cvss", "av")) else None

def extract_cves_from_data(data):
    cve_list = []
    cve_table = data.get("CVE_Table") or []

    if not cve_table:
        all_tables = data.get("all_tables") or {}
        for _, table_data in all_tables.items():
            headers = table_data.get("headers") or []
            rows = table_data.get("rows") or []
            if any("third-party component" in str(h).lower() for h in headers):
                continue
            if any("third-party component" in str(v).lower() for r in rows for v in r.values()):
                continue
            if any(any(keyword.lower() in h.lower() for h in headers) for keyword in CVE_HEADER_NAMES):
                cve_table = rows
                break

    for row in cve_table:
        if not isinstance(row, dict):
            continue
        cve_ids = []
        for key, value in row.items():
            if "CVE" in key.upper():
                text_val = value.get("text") if isinstance(value, dict) else str(value)
                if text_val:
                    cve_ids.extend(re.findall(r"CVE-\d{4}-\d{4,7}", text_val.upper()))
        if not cve_ids:
            continue

        description, cvss_score, cvss_vector = None, None, None
        for key, value in row.items():
            key_lower = key.lower()
            val_text = value.get("text") if isinstance(value, dict) else str(value)

            if "desc" in key_lower:
                description = clean_description(val_text)
            elif "cvss" in key_lower and "vector" not in key_lower:
                try:
                    cvss_score = float(val_text)
                except:
                    cvss_score = None
            elif "vector" in key_lower:
                cvss_vector = clean_vector(val_text)

        for cid in cve_ids:
            cve_list.append({
                "cve_id": cid,
                "description": description,
                "severity": None,  # always NULL for CVE table
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector
            })

    return cve_list

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
                    advisory_id = (raw_data.get("ArticleProperties", {}) or {}).get("Article Number") or raw_data.get("Link")
                    if not advisory_id: continue

                    # 1. Advisories
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("Title"),
                        raw_data.get("Severity"),
                        parse_date(raw_data.get("Published")),
                        parse_date(raw_data.get("Updated")),
                        raw_data.get("Link")
                    )
                    
                    cve_entries = extract_cves_from_data(raw_data)
                    for entry in cve_entries:
                        cve_id = entry["cve_id"]
                        cve_key = (vendor_id, cve_id)
                        
                        # 2. CVEs
                        cves[cve_key] = (
                            vendor_id, cve_id,
                            None, # cwe_id
                            clean_text(entry.get("description")),
                            None, # severity
                            safe_numeric(entry.get("cvss_score")),
                            entry.get("cvss_vector"),
                            None, None, # initial/latest release dates
                            raw_data.get("Link") # reference_url
                        )
                        
                        # 3. Product Map
                        cve_product_maps[cve_key] = (vendor_id, cve_id, None, None)
                        
                        # 4. Map
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")
                
                # --- SQL LOGIC: Living Database + Sequence Sync ---

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) 
                        VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET 
                        title=EXCLUDED.title, 
                        severity=EXCLUDED.severity, 
                        initial_release_date=EXCLUDED.initial_release_date, 
                        latest_update_date=EXCLUDED.latest_update_date,
                        advisory_url=EXCLUDED.advisory_url;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        description=COALESCE(EXCLUDED.description, cves.description), 
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
                logger.info(f"✅ Normalization complete for {len(rows)} {VENDOR_NAME} records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()



'''
# Dell_normal.py (Production Version with All Fixes)
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
logger = logging.getLogger("dell_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Dell EMC"

# --- Helper Functions ---
def clean_text(text):
    if not text: return None
    return re.sub(r"\s+", " ", str(text).replace("\n", " ")).strip()


def parse_date(date_str):
    if not date_str:
        return None
    for fmt in ("%b %d %Y", "%d %b %Y", "%d %B %Y"):
        try:
            return datetime.strptime(str(date_str).strip(), fmt).date()
        except:
            continue
    return None


def safe_numeric(value):
    if not value: return None
    match = re.search(r"(\d+\.\d+|\d+)", str(value))
    if match:
        try: return float(match.group(1))
        except (ValueError, TypeError): return None
    return None






CVE_HEADER_NAMES = ["Proprietary Code CVEs", "Proprietary Code CVE"]

def clean_description(desc):
    if not desc or len(desc.strip()) <= 20:
        return None
    return desc.strip()

def clean_vector(vector):
    if not vector:
        return None
    # Remove NVD reference text (flexible for http/https and spacing)
    vector = re.sub(
        r"See NVD\s*\(https?://nvd\.nist\.gov[^\)]*\)\s*for\s*individual scores for each CVE\.?",
        "",
        vector,
        flags=re.IGNORECASE
    )
    vector = vector.strip()
    return vector if vector.lower().startswith(("cvss", "av")) else None

def extract_cves_from_data(data):
    cve_list = []
    cve_table = data.get("CVE_Table") or []

    if not cve_table:
        all_tables = data.get("all_tables") or {}
        for _, table_data in all_tables.items():
            headers = table_data.get("headers") or []
            rows = table_data.get("rows") or []
            if any("third-party component" in str(h).lower() for h in headers):
                continue
            if any("third-party component" in str(v).lower() for r in rows for v in r.values()):
                continue
            if any(any(keyword.lower() in h.lower() for h in headers) for keyword in CVE_HEADER_NAMES):
                cve_table = rows
                break

    for row in cve_table:
        if not isinstance(row, dict):
            continue
        cve_ids = []
        for key, value in row.items():
            if "CVE" in key.upper():
                text_val = value.get("text") if isinstance(value, dict) else str(value)
                if text_val:
                    cve_ids.extend(re.findall(r"CVE-\d{4}-\d{4,7}", text_val.upper()))
        if not cve_ids:
            continue

        description, cvss_score, cvss_vector = None, None, None
        for key, value in row.items():
            key_lower = key.lower()
            val_text = value.get("text") if isinstance(value, dict) else str(value)

            if "desc" in key_lower:
                description = clean_description(val_text)
            elif "cvss" in key_lower and "vector" not in key_lower:
                try:
                    cvss_score = float(val_text)
                except:
                    cvss_score = None
            elif "vector" in key_lower:
                cvss_vector = clean_vector(val_text)

        for cid in cve_ids:
            cve_list.append({
                "cve_id": cid,
                "description": description,
                "severity": None,  # always NULL for CVE table
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector
            })

    return cve_list

# -------------------------
# Main normalization
# -------------------------
def extract_advisory_id(data, staging_id):
    title = data.get("Title") or ""
    match = re.search(r"(DSA-[^:]+):", title)
    if match:
        return match.group(1)
    art_num = data.get("ArticleProperties", {}).get("Article Number")
    if art_num:
        return art_num
    link = data.get("Link") or ""
    if link:
        return link.rstrip("/").split("/")[-1]
    return f"adv_{staging_id}"


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
                    advisory_id = (raw_data.get("ArticleProperties", {}) or {}).get("Article Number") or raw_data.get("Link")
                    if not advisory_id: continue

                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("Title"),
                        raw_data.get("Severity"),
                        parse_date(raw_data.get("Published")),
                        parse_date(raw_data.get("Updated")),
                        raw_data.get("Link")
                    )
                    
                    cve_entries = extract_cves_from_data(raw_data)
                    for entry in cve_entries:
                        cve_id = entry["cve_id"]
                        
                        cves[(vendor_id, cve_id)] = (
                            vendor_id, cve_id,
                            None, # cwe_id
                            clean_text(entry.get("description")),
                            None, # severity
                            safe_numeric(entry.get("cvss_score")),
                            entry.get("cvss_vector"),
                            None, None, # initial/latest release dates
                            raw_data.get("Link") # reference_url
                        )
                        cve_product_maps[(vendor_id, cve_id)] = (vendor_id, cve_id, None, None)
                        advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, initial_release_date=EXCLUDED.initial_release_date, latest_update_date=EXCLUDED.latest_update_date;
                    """, list(advisories.values()))
                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET description=EXCLUDED.description, cvss_score=EXCLUDED.cvss_score, cvss_vector=EXCLUDED.cvss_vector, reference_url=EXCLUDED.reference_url;
                    """, list(cves.values()))
                if cve_product_maps:
                    execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations=EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))
                if advisory_cves_map:
                    execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cves_map))

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
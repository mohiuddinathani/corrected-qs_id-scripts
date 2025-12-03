# Kubernetes_normal.py (Final Production Version)
import os
import re
import logging
import psycopg2
import sys
from psycopg2.extras import execute_values
from typing import Any, Dict, List, Optional
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("kubernetes_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Kubernetes"

# --- KUBERNETES-SPECIFIC PARSING LOGIC ---

SECTION_PATTERNS = {
    "affected_versions": ["Affected Versions", "Am I vulnerable?"],
    "fixed_versions": ["Fixed Versions"],
    "mitigation": ["How do I mitigate this vulnerability?", "Mitigation"],
}

DESCRIPTION_START_PATTERNS = [r"^(?!###)(?!\*\*)[A-Za-z0-9]"]
DESCRIPTION_STOP_PATTERNS = [r"^###", r"^\*\*", r"^CVSS[:\s]"]

def _extract_cves(text: str) -> Optional[List[str]]:
    if not text:
        return []
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))

def _extract_severity(text: str) -> Optional[str]:
    m = re.search(r"\b(Critical|High|Medium|Moderate|Low)\b", text, re.IGNORECASE)
    return m.group(1) if m else None

def _extract_cvss_score(text: str) -> Optional[float]:
    score_patterns = [
        r"\(Score[:\s]*([0-9]\.?[0-9]?)",
        r"Score[:\s]*([0-9]\.?[0-9]?)",
        r"\bscore of\s*([0-9]\.?[0-9]?)",
        r"\(([0-9]\.?[0-9]?),\s*(?:Critical|High|Medium|Moderate|Low)\)",
        r"\(([0-9]\.?[0-9]?)\)",
        r"CVSS Rating:\s*([0-9]\.?[0-9]?)",
        r"CVSS Rating: \w+ \(([0-9]\.?[0-9]?)\)",
        r"\(([0-9]\.?[0-9]?)\s*(?:Critical|High|Medium|Moderate|Low)\)",
        r"CVSS Rating\s+\w+\s*([0-9]\.?[0-9]?):"
    ]
    for pat in score_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            try:
                f = float(m.group(1))
                if 0.0 <= f <= 10.0:
                    return f
            except ValueError:
                continue
    return None

def _extract_cvss_vector(text: str) -> Optional[str]:
    m = re.search(r"(CVSS:(?:3\.0|3\.1)(?:/[A-Z]{1,3}:[A-Z]+)+)", text)
    return m.group(1) if m else None

def _extract_description(text: str) -> Optional[str]:
    lines = text.splitlines()
    buf, capturing = [], False
    for ln in lines:
        stripped = ln.strip()
        if not stripped and buf: break
        if any(re.match(p, stripped, re.IGNORECASE) for p in DESCRIPTION_START_PATTERNS):
            capturing = True
        if capturing:
            if any(re.match(stop, stripped, re.IGNORECASE) for stop in DESCRIPTION_STOP_PATTERNS):
                break
            buf.append(stripped)
    return " ".join(buf).strip() or None

def _extract_section(text: str, titles: List[str]) -> Optional[str]:
    for title in titles:
        pattern = re.compile(r"(?im)^(?:\#\#\#\#|\*\*)\s*" + re.escape(title) + r"\s*(?:\:|\*\*)\s*$")
        match = pattern.search(text)
        if match:
            content_start = match.end()
            next_section_match = re.search(r"^(?:#+|\*\*)\s*[A-Z]", text[content_start:], re.MULTILINE)
            if next_section_match:
                content_end = content_start + next_section_match.start()
                return text[content_start:content_end].strip()
            else:
                return text[content_start:].strip()
    return None

def normalize_content_text(text: str) -> Dict[str, Any]:
    if not text: return {}
    
    mitigation = _extract_section(text, SECTION_PATTERNS["mitigation"])
    fixed = _extract_section(text, SECTION_PATTERNS["fixed_versions"])
    recommendations = []
    if mitigation: recommendations.append(mitigation)
    if fixed: recommendations.append(f"Fixed Versions:\n{fixed}")
    
    return {
        "severity": _extract_severity(text),
        "cvss_score": _extract_cvss_score(text),
        "cvss_vector": _extract_cvss_vector(text),
        "cve_ids": _extract_cves(text),
        "description": _extract_description(text),
        "recommendations": "\n\n".join(recommendations) if recommendations else None,
    }

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

                advisories, cves, cve_product_maps, advisory_cve_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    advisory_id = str(raw_data.get("_kubernetes_io", {}).get("issue_number"))
                    if not advisory_id or advisory_id == '0': continue
                    
                    normalized = normalize_content_text(raw_data.get("content_text"))
                    
                    # 1. Advisory Record
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("summary"),
                        None, # Advisory Severity
                        datetime.strptime(raw_data.get("date_published")[:10], "%Y-%m-%d").date() if raw_data.get("date_published") else None,
                        None, # Latest Update Date
                        raw_data.get("url")
                    )
                    
                    all_cve_ids = normalized.get("cve_ids", [])
                    primary_cve_id = raw_data.get("id")
                    if primary_cve_id and primary_cve_id not in all_cve_ids:
                        all_cve_ids.append(primary_cve_id)
                    
                    for cve_id in all_cve_ids:
                        cve_key = (vendor_id, cve_id)
                        
                        # 2. CVE Record
                        cves[cve_key] = (
                            vendor_id, cve_id,
                            None, # cwe_id
                            normalized.get("description") or raw_data.get("summary"), 
                            normalized.get("severity"),
                            normalized.get("cvss_score"),
                            normalized.get("cvss_vector"),
                            None, None, # dates
                            raw_data.get("external_url")
                        )
                        
                        # 3. Product Map
                        cve_product_maps[cve_key] = (
                            vendor_id, cve_id, None, normalized.get("recommendations")
                        )
                        
                        # 4. Map
                        advisory_cve_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk database inserts...")
                
                # --- SQL LOGIC: Living Database + Sequence Sync ---

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) 
                        VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET 
                        title=EXCLUDED.title, 
                        severity=EXCLUDED.severity, 
                        initial_release_date=EXCLUDED.initial_release_date;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        description=COALESCE(EXCLUDED.description, cves.description), 
                        severity=COALESCE(EXCLUDED.severity, cves.severity), 
                        cvss_score=COALESCE(EXCLUDED.cvss_score, cves.cvss_score), 
                        cvss_vector=COALESCE(EXCLUDED.cvss_vector, cves.cvss_vector);
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
                        recommendations=EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))

                if advisory_cve_map:
                    execute_values(cur, """
                        INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) 
                        VALUES %s ON CONFLICT DO NOTHING;
                    """, list(advisory_cve_map))

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
# Kubernetes_normal.py (Production Version with Team's Logic)
import os
import re
import logging
import psycopg2
from psycopg2.extras import execute_values
from typing import Any, Dict, List, Optional
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("kubernetes_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Kubernetes"

# --- KUBERNETES-SPECIFIC PARSING LOGIC (from your team's script) ---

SECTION_PATTERNS = {
    "affected_versions": ["Affected Versions", "Am I vulnerable?"],
    "fixed_versions": ["Fixed Versions"],
    "mitigation": ["How do I mitigate this vulnerability?", "Mitigation"],
}

DESCRIPTION_START_PATTERNS = [r"^(?!###)(?!\*\*)[A-Za-z0-9]"]
DESCRIPTION_STOP_PATTERNS = [r"^###", r"^\*\*", r"^CVSS[:\s]"]

def _extract_cves(text: str) -> Optional[List[str]]:
    """
    Safely extracts a list of unique CVE IDs from text.
    Always returns a list, even if no CVEs are found.
    """
    if not text:
        return []
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))

def _extract_severity(text: str) -> Optional[str]:
    m = re.search(r"\b(Critical|High|Medium|Moderate|Low)\b", text, re.IGNORECASE)
    return m.group(1) if m else None

def _extract_cvss_score(text: str) -> Optional[float]:
    score_patterns = [
        r"\(Score[:\s]*([0-9]\.?[0-9]?)",
        r"Score[:\s]*([0-9]\.?[0-9]?)",
        r"\bscore of\s*([0-9]\.?[0-9]?)",
        r"\(([0-9]\.?[0-9]?),\s*(?:Critical|High|Medium|Moderate|Low)\)",
        r"\(([0-9]\.?[0-9]?)\)",
        r"CVSS Rating:\s*([0-9]\.?[0-9]?)",
        r"CVSS Rating: \w+ \(([0-9]\.?[0-9]?)\)",
        r"\(([0-9]\.?[0-9]?)\s*(?:Critical|High|Medium|Moderate|Low)\)",
        r"CVSS Rating\s+\w+\s*([0-9]\.?[0-9]?):"
    ]
    for pat in score_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            try:
                f = float(m.group(1))
                if 0.0 <= f <= 10.0:
                    return f
            except ValueError:
                continue
    return None

def _extract_cvss_vector(text: str) -> Optional[str]:
    m = re.search(r"(CVSS:(?:3\.0|3\.1)(?:/[A-Z]{1,3}:[A-Z]+)+)", text)
    return m.group(1) if m else None

def _extract_description(text: str) -> Optional[str]:
    lines = text.splitlines()
    buf, capturing = [], False
    for ln in lines:
        stripped = ln.strip()
        if not stripped and buf: break
        if any(re.match(p, stripped, re.IGNORECASE) for p in DESCRIPTION_START_PATTERNS):
            capturing = True
        if capturing:
            if any(re.match(stop, stripped, re.IGNORECASE) for stop in DESCRIPTION_STOP_PATTERNS):
                break
            buf.append(stripped)
    return " ".join(buf).strip() or None

def _extract_section(text: str, titles: List[str]) -> Optional[str]:
    for title in titles:
        pattern = re.compile(r"(?im)^(?:\#\#\#\#|\*\*)\s*" + re.escape(title) + r"\s*(?:\:|\*\*)\s*$")
        match = pattern.search(text)
        if match:
            content_start = match.end()
            next_section_match = re.search(r"^(?:#+|\*\*)\s*[A-Z]", text[content_start:], re.MULTILINE)
            if next_section_match:
                content_end = content_start + next_section_match.start()
                return text[content_start:content_end].strip()
            else:
                return text[content_start:].strip()
    return None

def normalize_content_text(text: str) -> Dict[str, Any]:
    """Your team's original function to parse the content_text block."""
    if not text: return {}
    
    mitigation = _extract_section(text, SECTION_PATTERNS["mitigation"])
    fixed = _extract_section(text, SECTION_PATTERNS["fixed_versions"])
    recommendations = []
    if mitigation: recommendations.append(mitigation)
    if fixed: recommendations.append(f"Fixed Versions:\n{fixed}")
    
    return {
        "severity": _extract_severity(text),
        "cvss_score": _extract_cvss_score(text),
        "cvss_vector": _extract_cvss_vector(text),
        "cve_ids": _extract_cves(text),
        "description": _extract_description(text),
        "recommendations": "\n\n".join(recommendations) if recommendations else None,
    }

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

                advisories, cves, cve_product_maps, advisory_cve_map = {}, {}, {}, set()

                for staging_id, raw_data in tqdm(rows, desc=f"Parsing {VENDOR_NAME} Data"):
                    advisory_id = str(raw_data.get("_kubernetes_io", {}).get("issue_number"))
                    if not advisory_id or advisory_id == '0': continue
                    
                    # Run the team's parsing logic
                    normalized = normalize_content_text(raw_data.get("content_text"))
                    
                    # Advisory Record - severity is NULL per your rule
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, raw_data.get("summary"),
                        None, # Advisory Severity
                        datetime.strptime(raw_data.get("date_published")[:10], "%Y-%m-%d").date() if raw_data.get("date_published") else None,
                        None, # Latest Update Date
                        raw_data.get("url")
                    )
                    
                    all_cve_ids = normalized.get("cve_ids", [])
                    primary_cve_id = raw_data.get("id")
                    if primary_cve_id and primary_cve_id not in all_cve_ids:
                        all_cve_ids.append(primary_cve_id)
                    
                    for cve_id in all_cve_ids:
                        # CVE Record - populating from the normalized data
                        cves[(vendor_id, cve_id)] = (
                            vendor_id, cve_id,
                            None, # cwe_id is NULL
                            normalized.get("description") or raw_data.get("summary"), # Fallback to summary
                            normalized.get("severity"),
                            normalized.get("cvss_score"),
                            normalized.get("cvss_vector"),
                            None, # initial_release_date is NULL
                            None, # latest_update_date is NULL
                            raw_data.get("external_url")
                        )
                        # Product Map
                        cve_product_maps[(vendor_id, cve_id)] = (
                            vendor_id, cve_id, None, normalized.get("recommendations")
                        )
                        # Advisory to CVE Map
                        advisory_cve_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk inserts...")
                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, initial_release_date=EXCLUDED.initial_release_date;
                    """, list(advisories.values()))
                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET description=EXCLUDED.description, severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score, cvss_vector=EXCLUDED.cvss_vector;
                    """, list(cves.values()))
                if cve_product_maps:
                    execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations=EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))
                if advisory_cve_map:
                    execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cve_map))

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
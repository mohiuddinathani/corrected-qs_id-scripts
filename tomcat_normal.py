# tomcat_normal.py (Final Production Version)
import os
import json
import re
import psycopg2
import logging
import sys
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv
from datetime import datetime
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("tomcat_normalizer")
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
}
VENDOR_NAME = "Apache Tomcat"

# --- Helper Functions ---
def extract_dates(paragraphs: list) -> list:
    text = " ".join(paragraphs)
    date_pattern = re.compile(r'\b((?:\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4})|(?:(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},\s+\d{4}))\b', re.IGNORECASE)
    date_strings = date_pattern.findall(text)
    dates = []
    for s in date_strings:
        for fmt in ('%d %B %Y', '%d %b %Y', '%B %d, %Y', '%b %d, %Y'):
            try:
                s_cleaned = re.sub(r'(\d+)(st|nd|rd|th)', r'\1', s[0])
                dates.append(datetime.strptime(s_cleaned, fmt).date())
                break
            except ValueError: continue
    return sorted(list(set(dates)))

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
                    logger.info("No new Tomcat records to process.")
                    return

                advisories, cves, cve_product_maps = {}, {}, {}
                advisory_cve_map = set()
                
                for staging_id, raw_data in tqdm(rows, desc="Parsing Staged Data"):
                    cve_id = raw_data.get("cve_id", "").strip()
                    if not cve_id: continue

                    url_parts = raw_data.get("advisory_url", "").split('/')
                    page_name = url_parts[-1].split('.')[0] if url_parts else "DEFAULT"
                    advisory_id = f"TOMCAT-{page_name.upper()}"
                    
                    paragraphs = raw_data.get("details_paragraphs", [])
                    description = paragraphs[0] if paragraphs else "No description provided."
                    all_dates = extract_dates(paragraphs)
                    release_date = all_dates[0] if all_dates else None

                    # 1. Advisory
                    advisories[advisory_id] = (
                        advisory_id, vendor_id, f"Apache Tomcat Security Bulletin ({page_name})",
                        raw_data.get("severity"), None, None,
                        raw_data.get("advisory_url", "").split('#')[0]
                    )

                    # 2. CVE Record
                    cves[cve_id] = (
                        vendor_id, cve_id, None, description, raw_data.get("severity"),
                        None, None, None, release_date, raw_data.get("advisory_url")
                    )
                    
                    # 3. Map
                    advisory_cve_map.add((advisory_id, vendor_id, cve_id))
                    
                    # 4. Product Map
                    recommendation = next((p for p in paragraphs if "are recommended to upgrade" in p.lower()), "See advisory for recommendations.")
                    cve_product_maps[cve_id] = (vendor_id, cve_id, None, recommendation)

                logger.info("Performing bulk database inserts...")
                
                # --- SQL LOGIC: Living Database + Sequence Sync ---

                if advisories:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) 
                        VALUES %s
                        ON CONFLICT (advisory_id) DO UPDATE SET 
                        title=EXCLUDED.title, 
                        severity=EXCLUDED.severity, 
                        latest_update_date=EXCLUDED.latest_update_date;
                    """, list(advisories.values()))

                if cves:
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) 
                        VALUES %s
                        ON CONFLICT (vendor_id, cve_id) DO UPDATE SET 
                        description=COALESCE(EXCLUDED.description, cves.description), 
                        severity=COALESCE(EXCLUDED.severity, cves.severity), 
                        latest_update_date=EXCLUDED.latest_update_date;
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
                logger.info(f"✅ Normalization complete for {len(rows)} staged records.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()

'''
# tomcat_normal.py (Final Production Version)
import os, json, re, psycopg2, logging, sys
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv
from datetime import datetime
from tqdm import tqdm

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"), "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
}
VENDOR_NAME = "Apache Tomcat"

# --- Helper Functions ---
def extract_dates(paragraphs: list) -> list:
    text = " ".join(paragraphs)
    date_pattern = re.compile(r'\b((?:\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4})|(?:(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},\s+\d{4}))\b', re.IGNORECASE)
    date_strings = date_pattern.findall(text)
    dates = []
    for s in date_strings:
        for fmt in ('%d %B %Y', '%d %b %Y', '%B %d, %Y', '%b %d, %Y'):
            try:
                s_cleaned = re.sub(r'(\d+)(st|nd|rd|th)', r'\1', s[0])
                dates.append(datetime.strptime(s_cleaned, fmt).date())
                break
            except ValueError: continue
    return sorted(list(set(dates)))

def main():
    logger.info(f"🚀 Starting Final {VENDOR_NAME} Processor (Pass 1)...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                cur.execute("SELECT staging_id, raw_data FROM vendor_staging_table WHERE vendor_name = %s AND processed = FALSE;", (VENDOR_NAME,))
                rows = cur.fetchall()
                if not rows:
                    logger.info("No new Tomcat records to process.")
                    return

                advisories, cves, cve_product_maps = {}, {}, {}
                advisory_cve_map = set()
                
                for staging_id, raw_data in tqdm(rows, desc="Parsing Staged Data"):
                    cve_id = raw_data.get("cve_id", "").strip()
                    if not cve_id: continue

                    url_parts = raw_data.get("advisory_url", "").split('/')
                    page_name = url_parts[-1].split('.')[0] if url_parts else "DEFAULT"
                    advisory_id = f"TOMCAT-{page_name.upper()}"
                    
                    paragraphs = raw_data.get("details_paragraphs", [])
                    description = paragraphs[0] if paragraphs else "No description provided."
                    all_dates = extract_dates(paragraphs)
                    release_date = all_dates[0] if all_dates else None

                    advisories[advisory_id] = (
                        advisory_id, vendor_id, f"Apache Tomcat Security Bulletin ({page_name})",
                        raw_data.get("severity"), None, None,
                        raw_data.get("advisory_url", "").split('#')[0]
                    )
                    cves[cve_id] = (
                        vendor_id, cve_id, None, description, raw_data.get("severity"),
                        None, None, None, release_date, raw_data.get("advisory_url")
                    )
                    advisory_cve_map.add((advisory_id,vendor_id, cve_id))
                    
                    recommendation = next((p for p in paragraphs if "are recommended to upgrade" in p.lower()), "See advisory for recommendations.")
                    cve_product_maps[cve_id] = (vendor_id, cve_id, None, recommendation)

                logger.info("Performing bulk inserts...")
                if advisories: execute_values(cur, "INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, latest_update_date=EXCLUDED.latest_update_date;", list(advisories.values()))
                if cves: execute_values(cur, "INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET description=COALESCE(EXCLUDED.description,cves.description), severity=COALESCE(EXCLUDED.severity,cves.severity), latest_update_date=EXCLUDED.latest_update_date;", list(cves.values()))
                if advisory_cve_map: execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id,vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cve_map))
                if cve_product_maps: execute_values(cur, "INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations=EXCLUDED.recommendations;", list(cve_product_maps.values()))

                processed_ids = tuple(row[0] for row in rows)
                if processed_ids:
                    cur.execute("UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} staged records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()
'''
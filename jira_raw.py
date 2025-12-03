# Jira_raw.py (Production Version)
import os
import json
import logging
import psycopg2
from psycopg2.extras import Json, execute_values
import requests
from dotenv import load_dotenv
from tqdm import tqdm

# --- Configuration ---
load_dotenv()
DB_CONFIG = {
    "host": os.getenv("DB_HOST"), "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"), "password": os.getenv("DB_PASS"),
    "port": os.getenv("DB_PORT"),
}
VENDOR_NAME = "Atlassian"
TABLE_NAME = "vendor_staging_table"
BASE_URL = "https://api.atlassian.com/vuln-transparency/v1/cves"

# --- Logging ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("jira_fetcher")

# --- Database Functions ---
def get_existing_urls(conn):
    with conn.cursor() as cur:
        cur.execute(f"SELECT source_url FROM {TABLE_NAME} WHERE vendor_name = %s", (VENDOR_NAME,))
        return {row[0] for row in cur.fetchall()}

def bulk_insert_staging(conn, records):
    if not records: return
    try:
        with conn.cursor() as cur:
            execute_values(cur, f"""
                INSERT INTO {TABLE_NAME} (vendor_name, source_url, raw_data, processed)
                VALUES %s ON CONFLICT (source_url) DO UPDATE
                SET raw_data = EXCLUDED.raw_data, processed = FALSE;
            """, records, template="(%s, %s, %s, false)")
        conn.commit()
    except Exception as e:
        logger.error(f"Bulk DB insert failed: {e}")
        conn.rollback()

# --- JIRA-SPECIFIC LOGIC (from your team's script) ---
def fetch_all_advisories(session):
    advisories = []
    url = BASE_URL
    pbar = tqdm(desc="Fetching Atlassian API Pages")
    while url:
        try:
            res = session.get(url, headers={"Accept": "application/json"}, timeout=30)
            res.raise_for_status()
            data = res.json()
            advisories.extend(data.get("resources", []))
            
            next_page_id = data.get("next_page_id")
            url = f"{BASE_URL}?page_id={next_page_id}" if next_page_id else None
            pbar.update(1)
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch {url}: {e}")
            break
    pbar.close()
    return advisories

# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Fetcher...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn, requests.Session() as session:
            all_advisories = fetch_all_advisories(session)
            if not all_advisories:
                logger.warning("No advisories found from the API.")
                return

            existing_urls = get_existing_urls(conn)
            new_records = []
            for adv in all_advisories:
                source_url = adv.get('atl_tracking_url') or adv.get('advisory_url')
                if not source_url and (cve_id := adv.get('cve_id')):
                    source_url = f"https://api.atlassian.com/vuln-transparency/v1/cves/{cve_id}"

                if source_url and source_url not in existing_urls:
                    new_records.append((VENDOR_NAME, source_url, Json(adv)))
            
            if not new_records:
                logger.info("✅ No new advisories to fetch.")
                return

            logger.info(f"Found {len(new_records)} new advisories to stage.")
            bulk_insert_staging(conn, new_records)
            logger.info("Bulk insert complete.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
    finally:
        logger.info(f"✅ {VENDOR_NAME} Fetcher finished.")

if __name__ == "__main__":
    main()
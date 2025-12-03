# aws_normal.py (Final Production Version)
import psycopg2
import json
import re
import os
import logging
import sys
from datetime import datetime
from dotenv import load_dotenv
from psycopg2.extras import execute_values, Json
from tqdm import tqdm

# --- Setup ---
load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("aws_normalizer")

# === PostgreSQL Config ===
DB_CONFIG = {
    'dbname': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASS'),
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT')
}
VENDOR_NAME = "Amazon Web Services"

# ==============================================================================
# === HELPER FUNCTIONS =========================================================
# ==============================================================================

def get_connection():
    """Establishes connection to PostgreSQL."""
    try:
        return psycopg2.connect(**DB_CONFIG)
    except psycopg2.OperationalError as e:
        logger.error(f"❌ Could not connect to PostgreSQL server. Error: {e}")
        sys.exit(1)

def format_date(date_string):
    """Parses date strings and converts to 'YYYY-MM-DD' format."""
    if not date_string or not isinstance(date_string, str): return None
    for fmt in ("%Y-%m-%d", "%b %d, %Y"):
        try:
            return datetime.strptime(date_string.strip(), fmt).strftime("%Y-%m-%d")
        except ValueError:
            pass
    return None

def fetch_data_from_db():
    """Fetches unprocessed raw data from the staging table for this vendor."""
    logger.info("⬇️  Connecting to the database to fetch staged data...")
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT staging_id, raw_data FROM vendor_staging_table WHERE processed = FALSE AND vendor_name = %s;",
                    (VENDOR_NAME,)
                )
                data = cur.fetchall()
        if not data:
            logger.info("✅ No new unprocessed AWS records found in the staging table.")
            return []
        logger.info(f"✅ Found {len(data)} new AWS records to process.")
        return data
    except psycopg2.Error as e:
        logger.error(f"❌ Could not fetch from the database. Error: {e}")
        return []

# ==============================================================================
# === NORMALIZATION LOGIC ======================================================
# ==============================================================================

def normalize(staged_data):
    """Processes raw AWS JSON data into structured dictionaries and sets."""
    logger.info("⚙️  Normalizing raw AWS data...")
    
    advisories, cves, advisory_cve_maps, cve_product_maps = {}, {}, set(), {}
    advisory_id_counter = {}

    for staging_id, raw in tqdm(staged_data, desc="Parsing Staged Data"):
        advisory_url = raw.get("url")
        
        # Handle failed scrapes gracefully
        if raw.get('error'):
            try:
                slug = advisory_url.strip('/').split('/')[-1]
                advisory_id = f"FAILED-{slug.upper()}"
                title = slug.replace('-', ' ').title()
            except:
                advisory_id = f"FAILED-STAGING-ID-{staging_id}"
                title = "Failed To Scrape Record"
            
            cve_id = f"NOCVE-{advisory_id}"
            advisories[advisory_id] = (advisory_id, VENDOR_NAME, title, "Unknown", None, None, advisory_url)
            cves[cve_id] = (cve_id, None, f"Scraping failed with error: {raw.get('error')}", None, None, "Unknown", None, None, advisory_url)
            advisory_cve_maps.add((advisory_id, cve_id))
            cve_product_maps[cve_id] = (cve_id, None, "Scraping failed, see advisory URL for details.")
            continue

        # Generate Advisory ID
        advisory_id = raw.get("bulletin_id")
        if not advisory_id or advisory_id == "Not Found":
            year = None
            cve_list = raw.get('cve_ids', [])
            if cve_list:
                match = re.search(r'CVE-(\d{4})', cve_list[0])
                if match: year = match.group(1)
            if not year:
                release_date_str = raw.get("release_date")
                if release_date_str:
                    try: year = datetime.strptime(release_date_str.strip(), "%Y-%m-%d").strftime("%Y")
                    except ValueError: pass
            if not year: year = str(datetime.now().year)
            sequence = advisory_id_counter.get(year, 0) + 1
            advisory_id_counter[year] = sequence
            advisory_id = f"AMZ-{year}-{sequence:03}"

        title = raw.get("title", "Title Not Found").strip()
        if title == "" or title == "Title Not Found": title = advisory_id
            
        description_parts = []
        if raw.get('description'): description_parts.append(f"### Summary\n{raw.get('description').strip()}")
        if raw.get('affected_products'): description_parts.append(f"### Affected Products\n{raw.get('affected_products').strip()}")
        if raw.get('resolution'): description_parts.append(f"### Resolution\n{raw.get('resolution').strip()}")
        if raw.get('workarounds'): description_parts.append(f"### Workarounds\n{raw.get('workarounds').strip()}")
        if raw.get('references'): description_parts.append(f"### References\n{raw.get('references').strip()}")
        if raw.get('acknowledgement'): description_parts.append(f"### Acknowledgement\n{raw.get('acknowledgement').strip()}")

        full_description = "\n\n".join(filter(None, description_parts))
        recommendation = raw.get('resolution') or raw.get('workarounds') or "See advisory for details."
        
        cve_list = raw.get('cve_ids', [])
        if not cve_list: cve_list = [f"NOCVE-{advisory_id}"]
        
        release_date = format_date(raw.get("release_date"))
        latest_date = format_date(raw.get("last_updated"))

        advisories[advisory_id] = (advisory_id, VENDOR_NAME, title, raw.get("severity", "Unknown"), release_date, latest_date, advisory_url)

        for cve_id in cve_list:
            cves[cve_id] = (
                cve_id, None, full_description, raw.get("severity", "Unknown"), None, None,
                None, None, advisory_url
            )
            advisory_cve_maps.add((advisory_id, cve_id))
            cve_product_maps[cve_id] = (cve_id, None, recommendation)
            
    return advisories, cves, advisory_cve_maps, cve_product_maps

# ==============================================================================
# === DATA LOADER ==============================================================
# ==============================================================================
def load_to_postgres(advisories, cves, advisory_cve_maps, cve_product_maps, staged_data):
    """Loads the structured data into the final relational tables using bulk methods."""
    if not advisories and not cves: return

    logger.info("📦 Loading normalized data into PostgreSQL using bulk methods...")
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                # Ensure Vendor Exists
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]

                # 1. ADVISORIES
                advisory_values = [(adv[0], vendor_id, *adv[2:]) for adv in advisories.values()]
                if advisory_values:
                    execute_values(cur, """
                        INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                        VALUES %s ON CONFLICT (advisory_id) DO UPDATE SET
                        title = EXCLUDED.title, severity = EXCLUDED.severity, 
                        initial_release_date = EXCLUDED.initial_release_date,
                        latest_update_date = EXCLUDED.latest_update_date, advisory_url = EXCLUDED.advisory_url;
                    """, advisory_values)

                # 2. CVES
                if cves:
                    cve_values = [(vendor_id, *val) for val in cves.values()]
                    execute_values(cur, """
                        INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
                        VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET
                        description = COALESCE(EXCLUDED.description, cves.description), 
                        severity = COALESCE(EXCLUDED.severity, cves.severity),
                        cvss_score = COALESCE(EXCLUDED.cvss_score, cves.cvss_score), 
                        cvss_vector = COALESCE(EXCLUDED.cvss_vector, cves.cvss_vector),
                        latest_update_date = EXCLUDED.latest_update_date,
                        reference_url = EXCLUDED.reference_url;
                    """, cve_values)

                # 3. ADVISORY-CVE MAP
                if advisory_cve_maps:
                    advisory_cve_values = [(adv_id, vendor_id, cve_id) for adv_id, cve_id in advisory_cve_maps]
                    execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", advisory_cve_values)
                
                # 4. PRODUCT MAP (With Sequence Sync)
                if cve_product_maps:
                    # --- CRITICAL FIX: Sync the Sequence ---
                    cur.execute("""
                        SELECT setval('qs_id_seq', COALESCE((
                            SELECT MAX(SUBSTRING(qs_id FROM 4)::INTEGER) 
                            FROM cve_product_map
                        ), 0) + 1);
                    """)

                    # Prepare values: (vendor_id, cve_id, affected_products_json, recommendations)
                    cve_product_values = [(vendor_id, val[0], Json(val[1]), val[2]) for val in cve_product_maps.values()]
                    
                    execute_values(cur, """
                        INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations)
                        VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET
                        affected_products_cpe = EXCLUDED.affected_products_cpe, 
                        recommendations = EXCLUDED.recommendations;
                    """, cve_product_values)

                # 5. MARK PROCESSED
                processed_ids = tuple(item[0] for item in staged_data)
                if processed_ids:
                    cur.execute("UPDATE vendor_staging_table SET processed = TRUE, processed_at = NOW() WHERE staging_id IN %s;", (processed_ids,))

                conn.commit()
        logger.info("✅ Successfully loaded data into the database.")
    except Exception as e:
        logger.error(f"❌ Database error: {e}", exc_info=True)

if __name__ == "__main__":
    staged_data = fetch_data_from_db()
    if staged_data:
        advisories, cves, advisory_cve_maps, cve_product_maps = normalize(staged_data)
        load_to_postgres(advisories, cves, advisory_cve_maps, cve_product_maps, staged_data)
        logger.info("\n🎉 AWS normalization script finished successfully!")



'''
# aws_normal.py (Final Production Version - Insertion Only)
import psycopg2
import json
import re
import os
from datetime import datetime
from dotenv import load_dotenv
from psycopg2.extras import execute_values, Json
from tqdm import tqdm

# --- Load Environment Variables from .env file ---
load_dotenv()

# === PostgreSQL Config ===
DB_CONFIG = {
    'dbname': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASS'),
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT')
}
VENDOR_NAME = "Amazon Web Services"

# ==============================================================================
# === HELPER & DATABASE FUNCTIONS ==============================================
# ==============================================================================

def get_connection():
    """Establishes connection to PostgreSQL."""
    try:
        return psycopg2.connect(**DB_CONFIG)
    except psycopg2.OperationalError as e:
        print(f"❌ Could not connect to PostgreSQL server. Error: {e}")
        exit()

def format_date(date_string):
    """Parses date strings and converts to 'YYYY-MM-DD' format."""
    if not date_string or not isinstance(date_string, str): return None
    for fmt in ("%Y-%m-%d", "%b %d, %Y"):
        try:
            return datetime.strptime(date_string.strip(), fmt).strftime("%Y-%m-%d")
        except ValueError:
            pass
    return None

def fetch_data_from_db():
    """Fetches unprocessed raw data from the staging table for this vendor."""
    print("⬇️  Connecting to the database to fetch staged data...")
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT staging_id, raw_data FROM vendor_staging_table WHERE processed = FALSE AND vendor_name = %s;",
                    (VENDOR_NAME,)
                )
                data = cur.fetchall()
        if not data:
            print("✅ No new unprocessed AWS records found in the staging table.")
            return []
        print(f"✅ Found {len(data)} new AWS records to process.")
        return data
    except psycopg2.Error as e:
        print(f"❌ Could not fetch from the database. Error: {e}")
        return []

# ==============================================================================
# === NORMALIZATION LOGIC (Unchanged) ==========================================
# ==============================================================================

def normalize(staged_data):
    """Processes raw AWS JSON data into structured dictionaries and sets."""
    print("⚙️  Normalizing raw AWS data...")
    
    advisories, cves, advisory_cve_maps, cve_product_maps = {}, {}, set(), {}
    advisory_id_counter = {}

    for staging_id, raw in tqdm(staged_data, desc="Parsing Staged Data"):
        advisory_url = raw.get("url")
        
        if raw.get('error'):
            try:
                slug = advisory_url.strip('/').split('/')[-1]
                advisory_id = f"FAILED-{slug.upper()}"
                title = slug.replace('-', ' ').title()
            except:
                advisory_id = f"FAILED-STAGING-ID-{staging_id}"
                title = "Failed To Scrape Record"
            
            cve_id = f"NOCVE-{advisory_id}"
            advisories[advisory_id] = (advisory_id, VENDOR_NAME, title, "Unknown", None, None, advisory_url)
            cves[cve_id] = (cve_id, None, f"Scraping failed with error: {raw.get('error')}", None, None, "Unknown", None, None, advisory_url)
            advisory_cve_maps.add((advisory_id, cve_id))
            cve_product_maps[cve_id] = (cve_id, None, "Scraping failed, see advisory URL for details.")
            continue

        advisory_id = raw.get("bulletin_id")
        if not advisory_id or advisory_id == "Not Found":
            year = None
            cve_list = raw.get('cve_ids', [])
            if cve_list:
                match = re.search(r'CVE-(\d{4})', cve_list[0])
                if match: year = match.group(1)
            if not year:
                release_date_str = raw.get("release_date")
                if release_date_str:
                    try: year = datetime.strptime(release_date_str.strip(), "%Y-%m-%d").strftime("%Y")
                    except ValueError: pass
            if not year: year = str(datetime.now().year)
            sequence = advisory_id_counter.get(year, 0) + 1
            advisory_id_counter[year] = sequence
            advisory_id = f"AMZ-{year}-{sequence:03}"

        title = raw.get("title", "Title Not Found").strip()
        if title == "" or title == "Title Not Found": title = advisory_id
            
        description_parts = []
        if raw.get('description'): description_parts.append(f"### Summary\n{raw.get('description').strip()}")
        if raw.get('affected_products'): description_parts.append(f"### Affected Products\n{raw.get('affected_products').strip()}")
        if raw.get('resolution'): description_parts.append(f"### Resolution\n{raw.get('resolution').strip()}")
        if raw.get('workarounds'): description_parts.append(f"### Workarounds\n{raw.get('workarounds').strip()}")
        if raw.get('references'): description_parts.append(f"### References\n{raw.get('references').strip()}")
        if raw.get('acknowledgement'): description_parts.append(f"### Acknowledgement\n{raw.get('acknowledgement').strip()}")

        full_description = "\n\n".join(filter(None, description_parts))
        recommendation = raw.get('resolution') or raw.get('workarounds') or "See advisory for details."
        
        cve_list = raw.get('cve_ids', [])
        if not cve_list: cve_list = [f"NOCVE-{advisory_id}"]
        
        release_date = format_date(raw.get("release_date"))
        latest_date = format_date(raw.get("last_updated"))

        advisories[advisory_id] = (advisory_id, VENDOR_NAME, title, raw.get("severity", "Unknown"), release_date, latest_date, advisory_url)

        for cve_id in cve_list:
            cves[cve_id] = (
                cve_id, None, full_description, raw.get("severity", "Unknown"), None, None,
                None, None, advisory_url
            )
            advisory_cve_maps.add((advisory_id, cve_id))
            cve_product_maps[cve_id] = (cve_id, None, recommendation)
            
    return advisories, cves, advisory_cve_maps, cve_product_maps

# ==============================================================================
# === DATA LOADER ==============================================================
# ==============================================================================
def load_to_postgres(advisories, cves, advisory_cve_maps, cve_product_maps):
    """Loads the structured data into the final relational tables using bulk methods."""
    if not advisories and not cves: return

    print("📦 Loading normalized data into PostgreSQL using bulk methods...")
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
            cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
            vendor_id = cur.fetchone()[0]

            # Replace vendor name with vendor_id in advisories data for insertion
            advisory_values = [(adv[0], vendor_id, *adv[2:]) for adv in advisories.values()]

            if advisory_values:
                print(f"...loading {len(advisory_values)} advisories")
                execute_values(cur, """
                    INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                    VALUES %s ON CONFLICT (advisory_id) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity, latest_update_date = EXCLUDED.latest_update_date, advisory_url = EXCLUDED.advisory_url;
                """, advisory_values)

            if cves:
                print(f"...loading {len(cves)} cves")
                cve_values = [(vendor_id, *val) for val in cves.values()]
                execute_values(cur, """
                    INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
                    VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET
                    description = COALESCE(EXCLUDED.description, cves.description), severity = COALESCE(EXCLUDED.severity, cves.severity),
                    cvss_score = COALESCE(EXCLUDED.cvss_score, cves.cvss_score), cvss_vector = COALESCE(EXCLUDED.cvss_vector, cves.cvss_vector),
                    latest_update_date = EXCLUDED.latest_update_date;
                """, cve_values)

            if advisory_cve_maps:
                print(f"...loading {len(advisory_cve_maps)} advisory-cve maps")
                advisory_cve_values = [(adv_id, vendor_id, cve_id) for adv_id, cve_id in advisory_cve_maps]
                execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id,vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", advisory_cve_values)
            
            if cve_product_maps:
                print(f"...loading {len(cve_product_maps)} cve-product maps")
                cve_product_values = [(vendor_id, val[0], Json(val[1]), val[2]) for val in cve_product_maps.values()]
                execute_values(cur, """
                    INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations)
                    VALUES %s ON CONFLICT (vendor_id, cve_id) DO UPDATE SET
                    affected_products_cpe = EXCLUDED.affected_products_cpe, recommendations = EXCLUDED.recommendations;
                """, cve_product_values)

        conn.commit()
    print("✅ Successfully loaded data into the database.")


if __name__ == "__main__":
    # The create_normalized_tables() call has been removed.
    staged_data = fetch_data_from_db()
    if staged_data:
        # Unpack the results from the normalize function
        advisories, cves, advisory_cve_maps, cve_product_maps = normalize(staged_data)
        load_to_postgres(advisories, cves, advisory_cve_maps, cve_product_maps)

        # Update the processed flag in the staging table after loading
        with get_connection() as conn:
            with conn.cursor() as cur:
                processed_ids = tuple(item[0] for item in staged_data)
                if processed_ids:
                    cur.execute("UPDATE vendor_staging_table SET processed = TRUE WHERE staging_id IN %s;", (processed_ids,))
        print("\n🎉 AWS normalization script finished successfully!")

'''
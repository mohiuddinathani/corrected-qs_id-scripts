# jenkins_normal.py (Final Production Version - Final)
import os
import re
import logging
import sys
from datetime import datetime
import psycopg2
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from tqdm import tqdm

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("jenkins_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "Jenkins"

# --- Helper Functions ---
def parse_date(date_string):
    if not date_string: return None
    try: return datetime.strptime(date_string, '%Y-%m-%d').date()
    except (ValueError, TypeError): return None

def get_text_from_header(soup, header_text_regex):
    header_tag = soup.find('th', string=re.compile(header_text_regex, re.I))
    return header_tag.find_next_sibling('td').get_text(strip=True) if header_tag and header_tag.find_next_sibling('td') else None

# --- Main Orchestrator ---
def main():
    logger.info("🚀 Starting Jenkins Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                # Ensure Vendor Exists
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]
                
                # Fetch Staging Data
                cur.execute("SELECT staging_id, raw_data, source_url FROM vendor_staging_table WHERE vendor_name = 'Jenkins' AND processed = FALSE;")
                rows = cur.fetchall()

                if not rows:
                    logger.info("No new Jenkins records to process.")
                    return
                
                logger.info(f"Normalizing {len(rows)} Jenkins records...")
                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data, advisory_url in tqdm(rows, desc="Processing Advisories"):
                    html_content = raw_data.get('html_content')
                    if not html_content: continue
                        
                    soup = BeautifulSoup(html_content, 'lxml')
                    
                    # --- Strategy 1: Modern Layout ---
                    if soup.find('table', class_='jenkins-advisory__table'):
                        advisory_id = get_text_from_header(soup, r'^(Advisory )?ID$')
                        if not advisory_id: continue
                        
                        initial_date = parse_date(get_text_from_header(soup, r'^Published$'))
                        updated_date = parse_date(get_text_from_header(soup, r'^Updated$'))
                        severity = get_text_from_header(soup, r'^Severity$')
                        
                        advisories[advisory_id] = (advisory_id, vendor_id, soup.find('h1').get_text(strip=True), severity, initial_date, updated_date, advisory_url)
                        
                        desc = (d.get_text(strip=True) if (d := soup.find('h2', string='Description')) and (p := d.find_next('p')) else "N/A")
                        recs_tag = soup.find('h2', string=re.compile(r'Solution|Fix', re.I))
                        recs = recs_tag.find_next('p').get_text(strip=True) if recs_tag and recs_tag.find_next('p') else "See advisory URL."

                        if vuln_header := soup.find('h2', string='Vulnerabilities'):
                            if vuln_table := vuln_header.find_next('table'):
                                for row in vuln_table.select('tbody tr'):
                                    cells = row.find_all('td')
                                    if len(cells) < 3: continue
                                    cve_id, cvss_text, cwe_text = cells[0].get_text(strip=True), cells[1].get_text(strip=True), cells[2].get_text(strip=True)
                                    if not cve_id.startswith("CVE-"): continue
                                    
                                    cve_key = (vendor_id, cve_id)
                                    cves[cve_key] = (
                                        vendor_id, cve_id, 
                                        (re.search(r'(CWE-\d+)', cwe_text) or (None,))[0], 
                                        desc, severity, 
                                        (re.search(r'(\d+\.\d+)', cvss_text) or (None,))[0], 
                                        (re.search(r'\((CVSS:[^)]+)\)', cvss_text) or (None,))[0],
                                        initial_date, updated_date, advisory_url
                                    )
                                    cve_product_maps[cve_key] = (vendor_id, cve_id, None, recs)
                                    advisory_cves_map.add((advisory_id, vendor_id, cve_id))
                    
                    # --- Strategy 2: Old & Ancient Layouts ---
                    else:
                        title_tag = soup.find('h1')
                        if not title_tag: continue
                        title = title_tag.get_text(strip=True)
                        if not (advisory_match := re.search(r'(\d{4}-\d{2}-\d{2})', title)): continue
                        
                        advisory_id = f"SECURITY-{advisory_match.group(1)}"
                        initial_date = parse_date(advisory_match.group(1))
                        
                        recs = "See advisory URL."
                        if recs_tag := soup.find('h2', string=re.compile(r'Fix|Solution', re.I)):
                            next_el = recs_tag.find_next_sibling()
                            if next_el and next_el.name in ['ul', 'ol']:
                                recs = '\n'.join(li.get_text(strip=True) for li in next_el.find_all('li'))
                            elif next_el and next_el.name in ['div', 'p']:
                                recs = next_el.get_text(strip=True, separator='\n')

                        
                        cves_found_in_advisory = 0
                        highest_severity_level = 0
                        highest_severity_str = None
                        severity_map = {"high": 3, "medium": 2, "low": 1}

                        if desc_header := soup.find('h2', string=re.compile(r'^Descriptions?$')):
                            for h3 in desc_header.find_all_next('h3'):
                                if h3.find_previous('h2') != desc_header: break
                                if not (strong_tag := h3.find_next_sibling('strong')) or not (cve_match := re.search(r'(CVE-\d{4}-\d{4,})', strong_tag.get_text())): continue
                                
                                cves_found_in_advisory += 1
                                cve_id = cve_match.group(1)
                                
                                description = "No description found"
                                if desc_strong := h3.find_next('strong', string='Description:'):
                                    desc_divs = desc_strong.find_next_siblings('div', class_='paragraph')
                                    description = ' '.join(p.get_text(strip=True) for p in desc_divs)
                                
                                severity, cvss_vector = None, None
                                if sev_strong := h3.find_next('strong', string=re.compile(r'Severity', re.I)):
                                    next_tag = sev_strong.find_next(['a', 'span'])
                                    if next_tag:
                                        severity = next_tag.get_text(strip=True).lower()
                                        if next_tag.name == 'a' and 'href' in next_tag.attrs and (vector_match := re.search(r'#(CVSS:.*)', next_tag['href'])):
                                            cvss_vector = vector_match.group(1)
                                    elif sev_strong.next_sibling:
                                        severity = str(sev_strong.next_sibling).strip().lower()

                                
                                if severity and severity_map.get(severity, 0) > highest_severity_level:
                                    highest_severity_level = severity_map.get(severity, 0)
                                    highest_severity_str = severity.capitalize()

                                cve_key = (vendor_id, cve_id)
                                cves[cve_key] = (vendor_id, cve_id, None, description, severity.capitalize() if severity else None, None, cvss_vector, initial_date, initial_date, advisory_url)
                                cve_product_maps[cve_key] = (vendor_id, cve_id, None, recs)
                                advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                        advisories[advisory_id] = (advisory_id, vendor_id, title, highest_severity_str, initial_date, initial_date, advisory_url)

                        if cves_found_in_advisory == 0:
                            if vuln_header := soup.find('h2', id='vulnerability'):
                                cve_id = f"NOCVE-{advisory_id}"
                                description = " ".join([p.get_text(strip=True) for p in vuln_header.find_next('div', class_='sectionbody').find_all('p')])
                                cve_key = (vendor_id, cve_id)
                                cves[cve_key] = (vendor_id, cve_id, None, description, "Unknown", None, None, initial_date, initial_date, advisory_url)
                                cve_product_maps[cve_key] = (vendor_id, cve_id, None, recs)
                                advisory_cves_map.add((advisory_id, vendor_id, cve_id))

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
                        cwe_id=COALESCE(EXCLUDED.cwe_id, cves.cwe_id),
                        description=COALESCE(EXCLUDED.description, cves.description), 
                        severity=COALESCE(EXCLUDED.severity, cves.severity), 
                        cvss_score=COALESCE(EXCLUDED.cvss_score, cves.cvss_score), 
                        cvss_vector=COALESCE(EXCLUDED.cvss_vector, cves.cvss_vector), 
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
                logger.info(f"✅ Normalization complete for {len(rows)} records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()


'''
# jenkins_normal.py (Production Version - Final)
import os
import re
import logging
from datetime import datetime
import psycopg2
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from tqdm import tqdm

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("jenkins_normalizer")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "Jenkins"

# --- Helper Functions ---
def parse_date(date_string):
    if not date_string: return None
    try: return datetime.strptime(date_string, '%Y-%m-%d').date()
    except (ValueError, TypeError): return None

def get_text_from_header(soup, header_text_regex):
    header_tag = soup.find('th', string=re.compile(header_text_regex, re.I))
    return header_tag.find_next_sibling('td').get_text(strip=True) if header_tag and header_tag.find_next_sibling('td') else None

# --- Main Orchestrator ---
def main():
    logger.info("🚀 Starting Jenkins Processor...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING;", (VENDOR_NAME,))
                cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name = %s;", (VENDOR_NAME,))
                vendor_id = cur.fetchone()[0]
                
                cur.execute("SELECT staging_id, raw_data, source_url FROM vendor_staging_table WHERE vendor_name = 'Jenkins' AND processed = FALSE;")
                rows = cur.fetchall()

                if not rows:
                    logger.info("No new Jenkins records to process.")
                    return
                
                logger.info(f"Normalizing {len(rows)} Jenkins records...")
                advisories, cves, cve_product_maps, advisory_cves_map = {}, {}, {}, set()

                for staging_id, raw_data, advisory_url in tqdm(rows, desc="Processing Advisories"):
                    html_content = raw_data.get('html_content')
                    if not html_content: continue
                        
                    soup = BeautifulSoup(html_content, 'lxml')
                    
                    # --- Strategy 1: Modern Layout ---
                    if soup.find('table', class_='jenkins-advisory__table'):
                        advisory_id = get_text_from_header(soup, r'^(Advisory )?ID$')
                        if not advisory_id: continue
                        
                        initial_date = parse_date(get_text_from_header(soup, r'^Published$'))
                        updated_date = parse_date(get_text_from_header(soup, r'^Updated$'))
                        severity = get_text_from_header(soup, r'^Severity$')
                        
                        advisories[advisory_id] = (advisory_id, vendor_id, soup.find('h1').get_text(strip=True), severity, initial_date, updated_date, advisory_url)
                        
                        desc = (d.get_text(strip=True) if (d := soup.find('h2', string='Description')) and (p := d.find_next('p')) else "N/A")
                        recs_tag = soup.find('h2', string=re.compile(r'Solution|Fix', re.I))
                        recs = recs_tag.find_next('p').get_text(strip=True) if recs_tag and recs_tag.find_next('p') else "See advisory URL."

                        if vuln_header := soup.find('h2', string='Vulnerabilities'):
                            if vuln_table := vuln_header.find_next('table'):
                                for row in vuln_table.select('tbody tr'):
                                    cells = row.find_all('td')
                                    if len(cells) < 3: continue
                                    cve_id, cvss_text, cwe_text = cells[0].get_text(strip=True), cells[1].get_text(strip=True), cells[2].get_text(strip=True)
                                    if not cve_id.startswith("CVE-"): continue
                                    
                                    cve_key = (vendor_id, cve_id)
                                    cves[cve_key] = (vendor_id, cve_id, (re.search(r'(CWE-\d+)', cwe_text) or (None,))[0], desc, severity, 
                                                     (re.search(r'(\d+\.\d+)', cvss_text) or (None,))[0], 
                                                     (re.search(r'\((CVSS:[^)]+)\)', cvss_text) or (None,))[0],
                                                     initial_date, updated_date, advisory_url)
                                    cve_product_maps[cve_key] = (vendor_id, cve_id, None, recs)
                                    advisory_cves_map.add((advisory_id, vendor_id, cve_id))
                    
                    # --- Strategy 2: Old & Ancient Layouts ---
                    else:
                        title = soup.find('h1').get_text(strip=True)
                        if not (advisory_match := re.search(r'(\d{4}-\d{2}-\d{2})', title)): continue
                        
                        advisory_id = f"SECURITY-{advisory_match.group(1)}"
                        initial_date = parse_date(advisory_match.group(1))
                        
                        # --- FIX: More robustly find recommendations ---
                        # --- FIXED: More robust recommendations extraction ---
                        recs = "See advisory URL."
                        if recs_tag := soup.find('h2', string=re.compile(r'Fix|Solution', re.I)):
                            # Prefer list (<ul>) or paragraph blocks following the header
                            next_el = recs_tag.find_next_sibling()
                            if next_el and next_el.name in ['ul', 'ol']:
                                recs = '\n'.join(li.get_text(strip=True) for li in next_el.find_all('li'))
                            elif next_el and next_el.name in ['div', 'p']:
                                recs = next_el.get_text(strip=True, separator='\n')

                        
                        cves_found_in_advisory = 0
                        highest_severity_level = 0
                        highest_severity_str = None
                        severity_map = {"high": 3, "medium": 2, "low": 1}

                        if desc_header := soup.find('h2', string=re.compile(r'^Descriptions?$')):
                            for h3 in desc_header.find_all_next('h3'):
                                if h3.find_previous('h2') != desc_header: break
                                if not (strong_tag := h3.find_next_sibling('strong')) or not (cve_match := re.search(r'(CVE-\d{4}-\d{4,})', strong_tag.get_text())): continue
                                
                                cves_found_in_advisory += 1
                                cve_id = cve_match.group(1)
                                
                                description = "No description found"
                                if desc_strong := h3.find_next('strong', string='Description:'):
                                    desc_divs = desc_strong.find_next_siblings('div', class_='paragraph')
                                    description = ' '.join(p.get_text(strip=True) for p in desc_divs)
                                
                                # --- FIX: Correctly find severity and vector ---
                                # --- FIXED: Find Severity (works for both <a> and plain text cases) ---
                                severity, cvss_vector = None, None
                                if sev_strong := h3.find_next('strong', string=re.compile(r'Severity', re.I)):
                                   # Sometimes it's followed by an <a>, sometimes plain text
                                    next_tag = sev_strong.find_next(['a', 'span'])
                                    if next_tag:
                                        severity = next_tag.get_text(strip=True).lower()
                                        if next_tag.name == 'a' and 'href' in next_tag.attrs and (vector_match := re.search(r'#(CVSS:.*)', next_tag['href'])):
                                            cvss_vector = vector_match.group(1)
                                    elif sev_strong.next_sibling:
                                        severity = str(sev_strong.next_sibling).strip().lower()

                                
                                if severity and severity_map.get(severity, 0) > highest_severity_level:
                                    highest_severity_level = severity_map.get(severity, 0)
                                    highest_severity_str = severity.capitalize()

                                cve_key = (vendor_id, cve_id)
                                cves[cve_key] = (vendor_id, cve_id, None, description, severity.capitalize() if severity else None, None, cvss_vector, initial_date, initial_date, advisory_url)
                                cve_product_maps[cve_key] = (vendor_id, cve_id, None, recs)
                                advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                        advisories[advisory_id] = (advisory_id, vendor_id, title, highest_severity_str, initial_date, initial_date, advisory_url)

                        if cves_found_in_advisory == 0:
                            if vuln_header := soup.find('h2', id='vulnerability'):
                                cve_id = f"NOCVE-{advisory_id}"
                                description = " ".join([p.get_text(strip=True) for p in vuln_header.find_next('div', class_='sectionbody').find_all('p')])
                                cve_key = (vendor_id, cve_id)
                                cves[cve_key] = (vendor_id, cve_id, None, description, "Unknown", None, None, initial_date, initial_date, advisory_url)
                                cve_product_maps[cve_key] = (vendor_id, cve_id, None, recs)
                                advisory_cves_map.add((advisory_id, vendor_id, cve_id))

                logger.info("Performing bulk database inserts...")
                if advisories: execute_values(cur, """
                    INSERT INTO advisories (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url) VALUES %s
                    ON CONFLICT (advisory_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, latest_update_date=EXCLUDED.latest_update_date;
                    """, list(advisories.values()))

                if cves: execute_values(cur, """
                    INSERT INTO cves (vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url) VALUES %s
                    ON CONFLICT (vendor_id, cve_id) DO UPDATE SET description=EXCLUDED.description, severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score, cvss_vector=EXCLUDED.cvss_vector, cwe_id=EXCLUDED.cwe_id, latest_update_date=EXCLUDED.latest_update_date;
                    """, list(cves.values()))

                if cve_product_maps: execute_values(cur, """
                    INSERT INTO cve_product_map (vendor_id, cve_id, affected_products_cpe, recommendations) VALUES %s
                    ON CONFLICT (vendor_id, cve_id) DO UPDATE SET recommendations=EXCLUDED.recommendations;
                    """, list(cve_product_maps.values()))

                if advisory_cves_map: execute_values(cur, "INSERT INTO advisory_cves_map (advisory_id, vendor_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", list(advisory_cves_map))

                processed_ids = tuple(row[0] for row in rows)
                if processed_ids: cur.execute("UPDATE vendor_staging_table SET processed = TRUE, processed_at = NOW() WHERE staging_id IN %s;", (processed_ids,))
                
                conn.commit()
                logger.info(f"✅ Normalization complete for {len(rows)} records.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()
'''
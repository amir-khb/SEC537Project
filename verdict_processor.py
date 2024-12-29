import re
import logging
import time
from datetime import datetime
from typing import Dict, Any
from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_utils import create_chrome_driver

def process_verdict(scan_data: Dict[str, Any], max_retries: int = 5) -> Dict[str, Any]:
    """Process a single verdict with retry logic"""
    retry_count = 0
    while retry_count < max_retries:
        driver = None
        try:
            driver = create_chrome_driver(use_proxy=True)
            scan_url = scan_data['scan_url']
            driver.get(scan_url)

            wait = WebDriverWait(driver, 20)
            wait.until(EC.presence_of_element_located((By.ID, "summary")))
            time.sleep(5)

            html_content = driver.page_source
            soup = BeautifulSoup(html_content, 'html.parser')

            verdict_data = extract_verdict_data(soup, scan_url)
            scan_data.update(verdict_data)
            break

        except Exception as e:
            retry_count += 1
            if retry_count == max_retries:
                scan_data['verdict'] = "Error"
                scan_data['verdict_metadata'] = {'error': str(e)}

        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass

    return scan_data

def extract_verdict_data(soup: BeautifulSoup, scan_url: str) -> Dict[str, Any]:
    """Extract verdict information from the page"""
    verdict = "No classification"
    verdict_metadata = {
        'timestamp': datetime.now().isoformat(),
        'scan_url': scan_url,
        'targeted_brands': [],
        'attacker_location': '',
        'attacker_hosting': '',
        'ip_info': '',
        'threats': ''
    }

    # Check for malicious warning
    if soup.find(string=lambda text: text and 'Malicious Activity!' in str(text)):
        verdict = "Malicious"

    # Check verdict text
    verdict_element = soup.select_one("#summary-container .alert")
    if verdict_element:
        verdict_text = verdict_element.get_text(strip=True).lower()
        if "malicious" in verdict_text:
            verdict = "Malicious"
        elif "suspicious" in verdict_text:
            verdict = "Suspicious"
        elif "benign" in verdict_text:
            verdict = "Benign"

    # Extract additional information
    summary_text = soup.select_one("#summary")
    if summary_text:
        location_match = re.search(r'located in ([^,]+) and belongs to ([^\.]+)',
                                 summary_text.get_text())
        if location_match:
            verdict_metadata['attacker_location'] = location_match.group(1).strip()
            verdict_metadata['attacker_hosting'] = location_match.group(2).strip()

    # Get IP information
    ip_details = soup.select_one("#ip-information")
    if ip_details:
        verdict_metadata['ip_info'] = ip_details.get_text(strip=True)

    # Get threats information
    threats = soup.select_one("#threats")
    if threats:
        verdict_metadata['threats'] = threats.get_text(strip=True)

    return {
        'verdict': verdict,
        'verdict_metadata': verdict_metadata
    }
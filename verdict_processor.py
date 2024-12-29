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

            # Wait for summary section
            wait = WebDriverWait(driver, 20)
            summary = wait.until(EC.presence_of_element_located((By.ID, "summary")))

            # Scroll to summary
            driver.execute_script("arguments[0].scrollIntoView(true);", summary)

            # Additional wait for dynamic content
            time.sleep(5)

            # Try to wait for brand information
            try:
                brand_info = wait.until(
                    EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Targeting these brands:')]"))
                )
            except Exception:
                pass

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
        'targeted_brands': []
    }

    # Check for malicious warning
    is_malicious = False
    if soup.find(string=lambda text: text and 'Malicious Activity!' in str(text)):
        verdict = "Malicious"
        is_malicious = True

    # Check verdict text for potentially malicious
    verdict_element = soup.select_one("span.red")
    if verdict_element and ("Malicious" in verdict_element.get_text() or
                            "Potentially Malicious" in verdict_element.get_text()):
        verdict = "Malicious"
        is_malicious = True

    # Only proceed with brand checking if the verdict is malicious
    if is_malicious:
        try:
            # Look for the simpletag that contains brand information
            brand_tag = soup.find('span', class_='simpletag')
            if brand_tag:
                # Find flag icon inside the simpletag
                flag = brand_tag.find('span', class_=lambda x: x and 'flag-icon-' in x)
                if flag:
                    country_code = flag.get('class')[1].replace('flag-icon-', '').upper()

                    # Get brand name and category
                    brand_text = brand_tag.get_text(strip=True)
                    brand_parts = brand_text.split('(')
                    if len(brand_parts) == 2:
                        brand_name = brand_parts[0].strip()
                        brand_category = brand_parts[1].replace(')', '').strip()

                        verdict_metadata['targeted_brands'].append({
                            'name': brand_name,
                            'category': brand_category,
                            'country': country_code
                        })
                        print(
                            f"Extracted brand information - Name: {brand_name}, Category: {brand_category}, Country: {country_code}")

        except Exception as e:
            print(f"Error extracting brand information for malicious verdict: {str(e)}")
            logging.exception("Error in brand extraction")

    return {
        'verdict': verdict,
        'verdict_metadata': verdict_metadata
    }
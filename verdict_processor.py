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
            # First try to find the targeting text itself
            targeting_section = soup.find(string=lambda text: text and 'Targeting these brands:' in str(text))
            if targeting_section:
                # Look for brand tags in the parent or next siblings
                parent = targeting_section.parent
                if parent:
                    print("Found targeting section in malicious verdict")

                    # Look for brand tags in multiple ways
                    brand_tags = []
                    brand_tags.extend(parent.parent.find_all('span', class_='simpletag'))
                    brand_tags.extend(parent.find_next_siblings('span', class_='simpletag'))

                    # If no simpletag, try finding any span with flag-icon
                    if not brand_tags:
                        brand_tags.extend(parent.parent.find_all('span', class_=lambda x: x and 'flag-icon-' in x))

                    print(f"Found {len(brand_tags)} potential brand tags")

                    for brand_tag in brand_tags:
                        # Find flag icon which might be in the current tag or a child
                        flag = brand_tag.find('span', class_=lambda x: x and 'flag-icon-' in x)
                        if not flag:
                            flag = brand_tag if 'flag-icon-' in brand_tag.get('class', []) else None

                        if flag:
                            country_code = [c for c in flag.get('class') if 'flag-icon-' in c][0]
                            country_code = country_code.replace('flag-icon-', '').upper()

                            # Get brand text, handling different structures
                            brand_text = brand_tag.get_text(strip=True)
                            print(f"Processing brand text: {brand_text}")

                            # Try different text patterns
                            if '(' in brand_text:
                                brand_parts = brand_text.split('(')
                                brand_name = brand_parts[0].strip()
                                brand_category = brand_parts[1].replace(')', '').strip()
                            else:
                                # If no category in parentheses, try to infer
                                brand_name = brand_text
                                brand_category = "Unknown"

                            verdict_metadata['targeted_brands'].append({
                                'name': brand_name,
                                'category': brand_category,
                                'country': country_code
                            })
                            print(f"Added brand: {brand_name} ({brand_category}) from {country_code}")

        except Exception as e:
            print(f"Error extracting brand information for malicious verdict: {str(e)}")
            logging.exception("Error in brand extraction")

    return {
        'verdict': verdict,
        'verdict_metadata': verdict_metadata
    }
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

            html_content = driver.page_source
            soup = BeautifulSoup(html_content, 'html.parser')

            verdict_data = extract_verdict_data(soup, driver, scan_url)
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

def extract_verdict_data(soup: BeautifulSoup, driver, scan_url: str) -> Dict[str, Any]:
    """Extract verdict information from the page"""
    verdict = "No classification"
    verdict_metadata = {
        'timestamp': datetime.now().isoformat(),
        'scan_url': scan_url,
        'targeted_brands': [],
        'location': None,
        'asn_org': None,
        'detected_technologies': []
    }

    # Extract ASN information from summary panel
    summary_panel = soup.find('div', class_='panel-body')
    if summary_panel:
        # Find the text containing ASN info
        location_text = summary_panel.get_text()

        # Extract ASN organization
        asn_match = re.search(r'belongs to\s+([^\.]+)', location_text)
        if asn_match:
            asn_org = asn_match.group(1).strip()
            verdict_metadata['asn_org'] = asn_org

            # Extract location from ASN org (last two characters if they're present)
            if ', ' in asn_org:
                verdict_metadata['location'] = asn_org.split(', ')[-1]

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

    # Only proceed with brand and technology checking if the verdict is malicious
    if is_malicious:
        # Extract targeted brands
        try:
            targeting_section = soup.find(string=lambda text: text and 'Targeting these brands:' in str(text))
            if targeting_section:
                parent = targeting_section.parent
                if parent:
                    brand_tags = parent.parent.find_all('span', class_='simpletag')
                    for brand_tag in brand_tags:
                        brand_text = brand_tag.get_text(strip=True)
                        if '(' in brand_text:
                            brand_parts = brand_text.split('(')
                            brand_name = brand_parts[0].strip()
                            brand_category = brand_parts[1].replace(')', '').strip()
                        else:
                            brand_name = brand_text
                            brand_category = "Unknown"

                        verdict_metadata['targeted_brands'].append({
                            'name': brand_name,
                            'category': brand_category
                        })
        except Exception as e:
            logging.exception("Error in brand extraction")

        # Extract detected technologies
        try:
            expand_buttons = driver.find_elements(By.XPATH, "//a[@data-toggle='collapse']")
            for button in expand_buttons:
                target_id = button.get_attribute("data-target")  # e.g., #collapse-wappa-jQuery
                associated_section = driver.find_element(By.CSS_SELECTOR, target_id)

                # Skip if already expanded
                if "in" in associated_section.get_attribute("class"):
                    continue

                # Click the button to expand the section
                driver.execute_script("arguments[0].click();", button)

                # Wait for the section to expand
                WebDriverWait(driver, 5).until(
                    lambda d: "in" in associated_section.get_attribute("class")
                )

            # Re-fetch the updated page source
            updated_html = driver.page_source
            updated_soup = BeautifulSoup(updated_html, 'html.parser')

            # Process expanded sections
            collapsed_sections = updated_soup.find_all("div", class_="collapse")
            for section in collapsed_sections:
                if "in" in section.get("class", []):
                    tech_name = section.find_previous("b").get_text(strip=True)

                    # Skip 'Resource Hash' and 'Security Headers'
                    if tech_name in ["Resource Hash", "Security Headers"]:
                        continue

                    # Extract full confidence information
                    confidence_element = section.find(string=re.compile(r'Overall confidence'))
                    if confidence_element:
                        # Locate parent or sibling element for the full confidence text
                        confidence_parent = confidence_element.parent
                        confidence_value = confidence_parent.find_next(string=re.compile(r'\d+%'))
                        if confidence_value:
                            confidence_text = f"{confidence_element.strip()} {confidence_value.strip()}"
                        else:
                            confidence_text = confidence_element.strip()
                    else:
                        confidence_text = None

                    detected_patterns = [li.get_text(strip=True) for li in section.find_all("li")]

                    verdict_metadata['detected_technologies'].append({
                        'technology': tech_name,
                        'confidence': confidence_text,
                        'patterns': detected_patterns
                    })

        except Exception as e:
            logging.exception("Error in technology extraction")

    return {
        'verdict': verdict,
        'verdict_metadata': verdict_metadata
    }

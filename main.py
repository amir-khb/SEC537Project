from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import json
import time
from datetime import datetime
import logging
from typing import List, Dict, Any, Optional, Tuple
import os
import random
from multiprocessing import Pool, cpu_count
from functools import partial


class URLScanRecentScraper:
    def __init__(self, output_file: str = "urlscan_results.json", verdicts_file: str = "urlscan_verdicts.json"):
        self.base_url = "https://urlscan.io"
        self.output_file = output_file
        self.verdicts_file = verdicts_file
        self.seen_urls = set()
        self.setup_logging()
        self.driver = None
        self.setup_driver()

    def setup_logging(self):
        """Configure logging settings"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def setup_driver(self):
        """Setup Chrome driver with proper error handling"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless=new')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-notifications')
            chrome_options.add_argument('--disable-popup-blocking')

            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            chrome_options.add_argument(f'user-agent={user_agent}')

            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.driver.set_page_load_timeout(30)
            logging.info("ChromeDriver setup successful")

        except Exception as e:
            logging.error(f"Error setting up ChromeDriver: {e}")
            raise

    def check_driver_health(self) -> bool:
        """Check if the WebDriver is still responsive"""
        try:
            self.driver.current_url
            return True
        except Exception:
            return False

    def get_page_content(self, url: str = None) -> str:
        """Fetch page content with enhanced retry logic"""
        max_retries = 5
        current_retry = 0
        backoff_factor = 1.5

        while current_retry < max_retries:
            try:
                logging.info(f"Attempting to fetch page (attempt {current_retry + 1}/{max_retries})")

                if not self.driver or not self.check_driver_health():
                    self.restart_driver()

                target_url = url if url else self.base_url
                self.driver.get(target_url)

                # Wait for content to load
                wait = WebDriverWait(self.driver, 15)
                if not url:  # Main page
                    wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "table")))
                else:  # Individual scan page
                    # Wait for summary information to load
                    wait.until(EC.presence_of_element_located((By.ID, "summary")))
                    # Additional wait for dynamic content
                    time.sleep(3)

                return self.driver.page_source

            except Exception as e:
                current_retry += 1
                logging.error(f"Error fetching page (attempt {current_retry}): {e}")

                if current_retry == max_retries:
                    logging.error("Max retries reached, restarting driver")
                    self.restart_driver()
                else:
                    wait_time = backoff_factor ** current_retry
                    time.sleep(min(wait_time, 30))

        return ""

    @staticmethod
    def create_driver():
        """Create a new Chrome driver instance for multiprocessing"""
        chrome_options = Options()
        chrome_options.add_argument('--headless=new')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--disable-notifications')
        chrome_options.add_argument('--disable-popup-blocking')

        user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        chrome_options.add_argument(f'user-agent={user_agent}')

        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_page_load_timeout(30)
        return driver

    @staticmethod
    def process_verdict(scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single verdict in a separate process"""
        try:
            driver = URLScanRecentScraper.create_driver()
            scan_url = scan_data['scan_url']

            try:
                # Wait for page to load
                driver.get(scan_url)
                wait = WebDriverWait(driver, 15)
                wait.until(EC.presence_of_element_located((By.ID, "summary")))
                time.sleep(3)

                html_content = driver.page_source
                soup = BeautifulSoup(html_content, 'html.parser')

                # Initialize verdict
                verdict = "No classification"

                # Look for malicious activity warning
                malicious_warning = soup.find(string=lambda text: text and 'Malicious Activity!' in str(text))
                if malicious_warning:
                    verdict = "Malicious"

                # Look for explicit verdict text
                verdict_element = soup.select_one("#summary-container .alert")
                if verdict_element:
                    verdict_text = verdict_element.get_text(strip=True)
                    if "malicious" in verdict_text.lower():
                        verdict = "Malicious"
                    elif "suspicious" in verdict_text.lower():
                        verdict = "Suspicious"
                    elif "benign" in verdict_text.lower():
                        verdict = "Benign"

                # Collect metadata
                metadata = {
                    'timestamp': datetime.now().isoformat(),
                    'scan_url': scan_url
                }

                # Get IP and location info
                ip_details = soup.select_one("#ip-information")
                if ip_details:
                    metadata['ip_info'] = ip_details.get_text(strip=True)

                # Get threat indicators
                threats = soup.select_one("#threats")
                if threats:
                    metadata['threats'] = threats.get_text(strip=True)

                scan_data['verdict'] = verdict
                scan_data['verdict_metadata'] = metadata

            except Exception as e:
                scan_data['verdict'] = "Error"
                scan_data['verdict_metadata'] = {'error': str(e)}

            finally:
                driver.quit()

            return scan_data

        except Exception as e:
            logging.error(f"Error in process_verdict: {e}")
            return {**scan_data, 'verdict': "Error", 'verdict_metadata': {'error': str(e)}}

    def get_scan_url_from_row(self, row) -> Optional[str]:
        """Extract the scan URL from a table row"""
        try:
            cells = row.find_all('td')
            if len(cells) < 2:
                return None

            url_cell = cells[1]
            link = url_cell.find('a')

            if link and link.get('href'):
                href = link.get('href')
                return f"{self.base_url}{href}" if href.startswith('/') else href

            url_text = url_cell.get_text(strip=True)
            if url_text:
                return f"{self.base_url}/result/{url_text}"

        except Exception as e:
            logging.error(f"Error extracting scan URL from row: {e}")
        return None

    def parse_recent_scans(self, html_content: str) -> List[Dict[str, Any]]:
        """Parse the recent scans table and prepare data for parallel processing"""
        if not html_content:
            return []

        soup = BeautifulSoup(html_content, 'html.parser')
        scan_data_list = []

        try:
            table = soup.find('table')
            if not table:
                logging.warning("Could not find recent scans table")
                return []

            for row in table.find_all('tr')[1:]:
                try:
                    cells = row.find_all('td')
                    if not cells or len(cells) < 7:
                        continue

                    url = cells[1].text.strip()
                    if not url or url == "Loading..." or url in self.seen_urls:
                        continue

                    scan_url = self.get_scan_url_from_row(row)
                    if not scan_url:
                        continue

                    country = ''
                    flag_span = row.find('span', class_='flag-icon')
                    if flag_span:
                        flag_classes = [c for c in flag_span.get('class', []) if c.startswith('flag-icon-')]
                        if flag_classes:
                            country = flag_classes[0].replace('flag-icon-', '').upper()

                    scan_data = {
                        'timestamp': datetime.now().isoformat(),
                        'url': url,
                        'scan_url': scan_url,
                        'age': cells[2].text.strip(),
                        'size': cells[3].text.strip(),
                        'requests': cells[4].text.strip(),
                        'ips': cells[5].text.strip(),
                        'threats': cells[6].text.strip(),
                        'country': country,
                        'status': 'locked' if row.find('img', {'alt': 'Private'}) else 'public'
                    }

                    scan_data_list.append(scan_data)
                    self.seen_urls.add(url)

                except Exception as e:
                    logging.error(f"Error parsing row: {e}")
                    continue

        except Exception as e:
            logging.error(f"Error parsing HTML: {e}")

        return scan_data_list

    def save_results(self, results: List[Dict[str, Any]], is_verdict: bool = False):
        """Save results to appropriate JSON file while maintaining existing data"""
        if not results:
            return

        try:
            output_file = self.verdicts_file if is_verdict else self.output_file
            existing_data = []

            if os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)

            if is_verdict:
                results = [result for result in results
                           if result['verdict'].lower() == 'malicious']
                if not results:
                    return

                seen_urls = {item['url'] for item in existing_data}
                results = [result for result in results
                           if result['url'] not in seen_urls]

                if not results:
                    logging.info("No new malicious URLs to add to verdicts file")
                    return

            existing_data.extend(results)

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(existing_data, f, indent=2, ensure_ascii=False)

            if is_verdict:
                logging.info(f"Saved {len(results)} new malicious URLs to {output_file}")
            else:
                logging.info(f"Saved {len(results)} new results to {output_file}")

        except Exception as e:
            logging.error(f"Error saving results: {e}")

    def restart_driver(self):
        """Safely restart the Chrome driver"""
        try:
            if self.driver:
                self.driver.quit()
        except Exception:
            pass

        time.sleep(5)
        self.setup_driver()

    def monitor_recent_scans(self, duration_minutes: int = 60, interval_seconds: int = 15):
        """Monitor recent scans using multiprocessing for verdict checking"""
        end_time = time.time() + (duration_minutes * 60)
        num_processes = max(1, cpu_count() - 1)  # Leave one CPU core free

        try:
            with Pool(processes=num_processes) as pool:
                while time.time() < end_time:
                    try:
                        # Get the initial scan data
                        html_content = self.get_page_content()
                        if html_content:
                            scan_data_list = self.parse_recent_scans(html_content)

                            if scan_data_list:
                                logging.info(f"Processing {len(scan_data_list)} scans using {num_processes} processes")

                                # Process verdicts in parallel
                                results = pool.map(URLScanRecentScraper.process_verdict, scan_data_list)

                                if results:
                                    # Save all scan results
                                    self.save_results(results)

                                    # Filter and save malicious results
                                    malicious_results = [result for result in results
                                                         if result['verdict'].lower() == 'malicious']

                                    if malicious_results:
                                        logging.info(f"Found {len(malicious_results)} malicious URLs")
                                        verdict_results = [{
                                            'url': result['url'],
                                            'scan_url': result['scan_url'],
                                            'verdict': result['verdict'],
                                            'metadata': result['verdict_metadata']
                                        } for result in malicious_results]
                                        self.save_results(verdict_results, is_verdict=True)
                                    else:
                                        logging.info("No malicious URLs found in this batch")

                        time.sleep(interval_seconds)

                    except Exception as e:
                        logging.error(f"Error in monitoring loop: {e}")
                        time.sleep(interval_seconds * 2)

        finally:
            if self.driver:
                self.driver.quit()


def main():
    scraper = URLScanRecentScraper()

    try:
        # Monitor for 24 hours by default
        scraper.monitor_recent_scans(duration_minutes=1440, interval_seconds=15)
    except KeyboardInterrupt:
        logging.info("Scraping interrupted by user")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
    finally:
        if scraper.driver:
            scraper.driver.quit()


if __name__ == "__main__":
    main()
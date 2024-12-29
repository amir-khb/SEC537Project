import concurrent
import queue
import random
from threading import Thread
import requests
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
from typing import List, Dict, Any, Optional
import os
from multiprocessing import Pool, cpu_count, Lock


class ProxyHandler:
    def __init__(self, max_proxies: int = 10):
        self.max_proxies = max_proxies
        self.working_proxies: List[Dict] = []
        self.proxy_lock = Lock()
        self.setup_logging()

    def setup_logging(self):
        """Configure logging settings"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def fetch_free_proxies(self) -> List[Dict]:
        """Fetch free proxies from multiple sources"""
        proxies = []

        # Source 1: free-proxy-list.net
        try:
            response = requests.get('https://free-proxy-list.net/', timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            proxy_table = soup.find('table')

            if proxy_table:
                rows = proxy_table.find_all('tr')[1:]  # Skip header
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 7:
                        ip = cols[0].text.strip()
                        port = cols[1].text.strip()
                        https = cols[6].text.strip()
                        if https == 'yes':
                            proxies.append({
                                'http': f'http://{ip}:{port}',
                                'https': f'http://{ip}:{port}'
                            })
        except Exception as e:
            logging.error(f"Error fetching from free-proxy-list.net: {e}")

        # Source 2: proxyscrape.com API
        try:
            response = requests.get(
                'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=yes&anonymity=all',
                timeout=10
            )
            for line in response.text.split('\n'):
                if ':' in line:
                    ip, port = line.strip().split(':')
                    proxies.append({
                        'http': f'http://{ip}:{port}',
                        'https': f'http://{ip}:{port}'
                    })
        except Exception as e:
            logging.error(f"Error fetching from proxyscrape.com: {e}")

        # Source 3: geonode.com API
        try:
            response = requests.get(
                'https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps',
                timeout=10
            )
            data = response.json()
            for proxy in data.get('data', []):
                ip = proxy.get('ip')
                port = proxy.get('port')
                if ip and port:
                    proxies.append({
                        'http': f'http://{ip}:{port}',
                        'https': f'https://{ip}:{port}'
                    })
        except Exception as e:
            logging.error(f"Error fetching from geonode.com: {e}")

        return proxies

    def validate_proxy(self, proxy: Dict) -> bool:
        """Validate a single proxy by testing connection to a reliable website"""
        test_urls = [
            'https://www.google.com',
            'https://www.cloudflare.com',
            'https://www.amazon.com'
        ]

        try:
            # Test with a random URL from the list
            test_url = random.choice(test_urls)
            response = requests.get(
                test_url,
                proxies=proxy,
                timeout=5,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
            )
            return response.status_code == 200
        except Exception:
            return False

    def validate_proxies_worker(self, proxy_queue: queue.Queue, valid_proxies: List[Dict], max_valid: int):
        """Worker function to validate proxies"""
        while True:
            try:
                proxy = proxy_queue.get_nowait()
            except queue.Empty:
                break

            if self.validate_proxy(proxy):
                with self.proxy_lock:
                    if len(valid_proxies) < max_valid:
                        valid_proxies.append(proxy)
                        logging.info(f"Found working proxy: {proxy}")

            proxy_queue.task_done()

    def validate_proxies(self, proxies: List[Dict]) -> List[Dict]:
        """Validate multiple proxies using threading"""
        proxy_queue = queue.Queue()
        valid_proxies = []

        # Fill the queue with proxies
        for proxy in proxies:
            proxy_queue.put(proxy)

        # Create and start worker threads
        num_threads = min(20, len(proxies))
        threads = []
        for _ in range(num_threads):
            t = Thread(target=self.validate_proxies_worker,
                       args=(proxy_queue, valid_proxies, self.max_proxies))
            t.daemon = True
            t.start()
            threads.append(t)

        # Wait for all proxies to be processed
        proxy_queue.join()

        # Wait for all threads to complete
        for t in threads:
            t.join()

        return valid_proxies[:self.max_proxies]

    def get_working_proxy(self) -> Optional[Dict]:
        """Get a random working proxy from the pool"""
        if not self.working_proxies:
            logging.info("Fetching and validating new proxies...")
            proxies = self.fetch_free_proxies()
            self.working_proxies = self.validate_proxies(proxies)

        if self.working_proxies:
            return random.choice(self.working_proxies)
        return None

    def refresh_proxies(self):
        """Refresh the proxy pool"""
        logging.info("Refreshing proxy pool...")
        proxies = self.fetch_free_proxies()
        self.working_proxies = self.validate_proxies(proxies)

class URLScanRecentScraper:
    def __init__(self, output_file: str = "urlscan_results.json", verdicts_file: str = "urlscan_verdicts.json"):
        self.base_url = "https://urlscan.io"
        self.output_file = output_file
        self.verdicts_file = verdicts_file
        self.seen_urls = set()
        self.setup_logging()
        self.driver = None
        self.proxy_handler = ProxyHandler(max_proxies=5)
        self.setup_driver()

    def setup_logging(self):
        """Configure logging settings"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def setup_driver(self):
        """Setup Chrome driver with proxy support and proper error handling"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless=new')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-notifications')
            chrome_options.add_argument('--disable-popup-blocking')

            # Add proxy if available
            proxy = self.proxy_handler.get_working_proxy()
            if proxy:
                proxy_server = proxy['https']
                chrome_options.add_argument(f'--proxy-server={proxy_server}')
                logging.info(f"Using proxy: {proxy_server}")

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
        """Fetch page content with enhanced retry logic and proxy rotation"""
        max_retries = 5
        current_retry = 0
        backoff_factor = 1.5
        timeout_messages = ["timeout: Timed out receiving message from renderer", "TimeoutException"]

        while current_retry < max_retries:
            try:
                logging.info(f"Attempting to fetch page (attempt {current_retry + 1}/{max_retries})")

                if not self.driver or not self.check_driver_health():
                    self.restart_driver()

                target_url = url if url else self.base_url
                self.driver.get(target_url)

                # Wait for content to load
                wait = WebDriverWait(self.driver, 20)  # Increased wait time
                if not url:  # Main page
                    wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "table")))
                else:  # Individual scan page
                    # Wait for summary information to load
                    wait.until(EC.presence_of_element_located((By.ID, "summary")))
                    # Additional wait for dynamic content
                    time.sleep(3)

                return self.driver.page_source

            except Exception as e:
                error_msg = str(e)
                current_retry += 1

                # Check if it's a timeout error
                if any(timeout_msg in error_msg for timeout_msg in timeout_messages):
                    logging.error(f"Timeout error fetching page (attempt {current_retry}): {e}")

                    # Force proxy rotation on timeout
                    if current_retry < max_retries:
                        logging.info("Rotating proxy and retrying...")
                        self.proxy_handler.refresh_proxies()  # Get fresh proxies
                        self.restart_driver()  # Restart with new proxy
                        wait_time = backoff_factor ** current_retry
                        time.sleep(min(wait_time, 30))
                        continue
                else:
                    logging.error(f"Error fetching page (attempt {current_retry}): {e}")

                if current_retry == max_retries:
                    logging.error("Max retries reached, giving up")
                    break
                else:
                    wait_time = backoff_factor ** current_retry
                    time.sleep(min(wait_time, 30))

        return ""

    def restart_driver(self):
        """Safely restart the Chrome driver with a new proxy"""
        try:
            if self.driver:
                self.driver.quit()
        except Exception:
            pass

        time.sleep(5)

        # Always get a new proxy when restarting
        self.proxy_handler.refresh_proxies()

        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless=new')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-notifications')
            chrome_options.add_argument('--disable-popup-blocking')

            # Get and apply new proxy
            proxy = self.proxy_handler.get_working_proxy()
            if proxy:
                proxy_server = proxy['https']
                chrome_options.add_argument(f'--proxy-server={proxy_server}')
                logging.info(f"Using new proxy: {proxy_server}")

            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            chrome_options.add_argument(f'user-agent={user_agent}')

            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.driver.set_page_load_timeout(30)
            logging.info("ChromeDriver restarted successfully with new proxy")

        except Exception as e:
            logging.error(f"Error restarting ChromeDriver: {e}")
            raise

    @staticmethod
    def create_driver():
        """Create a new Chrome driver instance for multiprocessing with proxy support"""
        chrome_options = Options()
        chrome_options.add_argument('--headless=new')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--disable-notifications')
        chrome_options.add_argument('--disable-popup-blocking')

        # Create a new proxy handler for this process
        proxy_handler = ProxyHandler(max_proxies=1)
        proxy = proxy_handler.get_working_proxy()
        if proxy:
            proxy_server = proxy['https']
            chrome_options.add_argument(f'--proxy-server={proxy_server}')

        user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        chrome_options.add_argument(f'user-agent={user_agent}')

        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_page_load_timeout(30)
        return driver

    @staticmethod
    def process_verdict(scan_data: Dict[str, Any], max_retries: int = 3) -> Dict[str, Any]:
        """Process a single verdict in a separate process with retry logic for timeouts"""
        retry_count = 0
        timeout_messages = ["timeout: Timed out receiving message from renderer", "TimeoutException"]

        while retry_count < max_retries:
            try:
                # Create a new proxy handler for each attempt
                proxy_handler = ProxyHandler(max_proxies=1)
                driver = None

                try:
                    # Setup Chrome with new proxy
                    chrome_options = Options()
                    chrome_options.add_argument('--headless=new')
                    chrome_options.add_argument('--no-sandbox')
                    chrome_options.add_argument('--disable-dev-shm-usage')
                    chrome_options.add_argument('--disable-gpu')
                    chrome_options.add_argument('--window-size=1920,1080')
                    chrome_options.add_argument('--disable-notifications')
                    chrome_options.add_argument('--disable-popup-blocking')

                    # Get and apply new proxy
                    proxy = proxy_handler.get_working_proxy()
                    if proxy:
                        proxy_server = proxy['https']
                        chrome_options.add_argument(f'--proxy-server={proxy_server}')
                        logging.info(f"Attempt {retry_count + 1}: Using proxy {proxy_server}")

                    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                    chrome_options.add_argument(f'user-agent={user_agent}')

                    service = Service(ChromeDriverManager().install())
                    driver = webdriver.Chrome(service=service, options=chrome_options)
                    driver.set_page_load_timeout(30)

                    scan_url = scan_data['scan_url']
                    driver.get(scan_url)

                    # Increased wait time for better reliability
                    wait = WebDriverWait(driver, 20)
                    wait.until(EC.presence_of_element_located((By.ID, "summary")))
                    time.sleep(5)  # Additional wait for dynamic content

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

                    # Extract targeted brands and their countries
                    targeted_brands = []
                    brands_section = soup.find(string=lambda text: text and 'Targeting these brands:' in str(text))
                    if brands_section and brands_section.parent:
                        brands_container = brands_section.parent.find_next_sibling()
                        if brands_container:
                            for brand in brands_container.find_all(['span', 'div']):
                                brand_name = None
                                category = None

                                brand_name_elem = brand.find('span', recursive=False)
                                if brand_name_elem:
                                    brand_name = brand_name_elem.get_text(strip=True)

                                category_text = brand.get_text(strip=True)
                                if '(' in category_text and ')' in category_text:
                                    category = category_text[
                                               category_text.find('(') + 1:category_text.find(')')].strip()

                                flag_span = brand.find_previous_sibling('span', class_='flag-icon')
                                brand_country = ''
                                if flag_span:
                                    flag_classes = [c for c in flag_span.get('class', []) if c.startswith('flag-icon-')]
                                    if flag_classes:
                                        brand_country = flag_classes[0].replace('flag-icon-', '').upper()

                                if category_text:
                                    targeted_brands.append({
                                        'name': brand_name if brand_name else category_text.split('(')[0].strip(),
                                        'category': category if category else '',
                                        'country': brand_country
                                    })

                    # Extract attacker info
                    attacker_info = {'country': '', 'hosting_company': ''}
                    summary_text = soup.select_one("#summary")
                    if summary_text:
                        location_text = summary_text.get_text()
                        import re
                        location_match = re.search(r'located in ([^,]+) and belongs to ([^\.]+)', location_text)
                        if location_match:
                            attacker_info['country'] = location_match.group(1).strip()
                            attacker_info['hosting_company'] = location_match.group(2).strip()

                    metadata = {
                        'timestamp': datetime.now().isoformat(),
                        'scan_url': scan_url,
                        'targeted_brands': targeted_brands,
                        'attacker_location': attacker_info['country'],
                        'attacker_hosting': attacker_info['hosting_company']
                    }

                    # Get additional details
                    ip_details = soup.select_one("#ip-information")
                    if ip_details:
                        metadata['ip_info'] = ip_details.get_text(strip=True)

                    threats = soup.select_one("#threats")
                    if threats:
                        metadata['threats'] = threats.get_text(strip=True)

                    scan_data['verdict'] = verdict
                    scan_data['verdict_metadata'] = metadata

                    # If we get here without errors, break the retry loop
                    break

                except Exception as e:
                    error_msg = str(e)
                    # Check if it's a timeout error
                    if any(timeout_msg in error_msg for timeout_msg in timeout_messages):
                        retry_count += 1
                        logging.warning(f"Timeout error on attempt {retry_count}. Retrying with new proxy...")
                        if retry_count < max_retries:
                            time.sleep(retry_count * 2)  # Exponential backoff
                            continue

                    scan_data['verdict'] = "Error"
                    scan_data['verdict_metadata'] = {'error': str(e)}

                finally:
                    if driver:
                        try:
                            driver.quit()
                        except Exception:
                            pass

            except Exception as e:
                logging.error(f"Outer error in process_verdict: {e}")
                scan_data['verdict'] = "Error"
                scan_data['verdict_metadata'] = {'error': str(e)}

        return scan_data


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
        """Safely restart the Chrome driver with a new proxy"""
        try:
            if self.driver:
                self.driver.quit()
        except Exception:
            pass

        time.sleep(5)

        # Refresh proxy pool periodically
        if random.random() < 0.2:  # 20% chance to refresh the entire proxy pool
            self.proxy_handler.refresh_proxies()

        self.setup_driver()

    def monitor_recent_scans(self, duration_minutes: int = 60, interval_seconds: int = 15):
        """Monitor recent scans using multiprocessing for verdict checking."""
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

                                    # Check for "verdict": "Error"
                                    for result in results:
                                        if result.get('verdict') == "Error":
                                            logging.info(f"Terminating program due to error verdict: {result}")
                                            raise SystemExit

                                    # Filter and save malicious results
                                    malicious_results = [
                                        result for result in results if result['verdict'].lower() == 'malicious'
                                    ]

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

                    except SystemExit:
                        logging.info("Program terminated due to error verdict")
                        break
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
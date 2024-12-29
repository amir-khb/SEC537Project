# import time
# import logging
# import json
# import os
# from datetime import datetime
# from typing import List, Dict, Any, Optional
# from bs4 import BeautifulSoup
# from selenium.webdriver.common.by import By
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from multiprocessing import Pool, cpu_count
# from proxy_handler import ProxyHandler
# from webdriver_utils import create_chrome_driver
# from verdict_processor import process_verdict
#
# class URLScanRecentScraper:
#     def __init__(self, output_file: str = "urlscan_results.json",
#                  verdicts_file: str = "urlscan_verdicts.json"):
#         self.base_url = "https://urlscan.io"
#         self.output_file = output_file
#         self.verdicts_file = verdicts_file
#         self.seen_urls = set()
#         self.setup_logging()
#         self.driver = None
#         self.setup_driver()
#
#     def setup_logging(self):
#         """Configure logging settings"""
#         logging.basicConfig(
#             level=logging.INFO,
#             format='%(asctime)s - %(levelname)s - %(message)s'
#         )
#
#     def setup_driver(self):
#         """Setup Chrome driver"""
#         self.driver = create_chrome_driver()
#
#     def get_scan_url_from_row(self, row) -> Optional[str]:
#         """Extract the scan URL from a table row"""
#         try:
#             cells = row.find_all('td')
#             if len(cells) < 2:
#                 return None
#
#             url_cell = cells[1]
#             link = url_cell.find('a')
#
#             if link and link.get('href'):
#                 href = link.get('href')
#                 return f"{self.base_url}{href}" if href.startswith('/') else href
#
#             url_text = url_cell.get_text(strip=True)
#             if url_text:
#                 return f"{self.base_url}/result/{url_text}"
#
#         except Exception as e:
#             logging.error(f"Error extracting scan URL from row: {e}")
#         return None
#
#     def get_page_content(self) -> str:
#         """Fetch page content"""
#         max_retries = 5
#         for attempt in range(max_retries):
#             try:
#                 if not self.driver:
#                     self.setup_driver()
#
#                 self.driver.get(self.base_url)
#                 wait = WebDriverWait(self.driver, 20)
#                 wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "table")))
#                 return self.driver.page_source
#
#             except Exception as e:
#                 logging.error(f"Error fetching page (attempt {attempt + 1}): {e}")
#                 if attempt == max_retries - 1:
#                     return ""
#                 time.sleep(2 ** attempt)  # Exponential backoff
#                 self.restart_driver()
#
#         return ""
#
#     def parse_recent_scans(self, html_content: str) -> List[Dict[str, Any]]:
#         """Parse the recent scans table"""
#         if not html_content:
#             return []
#
#         soup = BeautifulSoup(html_content, 'html.parser')
#         scan_data_list = []
#
#         try:
#             table = soup.find('table')
#             if not table:
#                 return []
#
#             for row in table.find_all('tr')[1:]:  # Skip header row
#                 try:
#                     cells = row.find_all('td')
#                     if len(cells) < 7:
#                         continue
#
#                     url = cells[1].text.strip()
#                     if not url or url == "Loading..." or url in self.seen_urls:
#                         continue
#
#                     scan_url = self.get_scan_url_from_row(row)
#                     if not scan_url:
#                         continue
#
#                     # Extract country from flag icon
#                     country = ''
#                     flag_span = row.find('span', class_='flag-icon')
#                     if flag_span:
#                         flag_classes = [c for c in flag_span.get('class', [])
#                                       if c.startswith('flag-icon-')]
#                         if flag_classes:
#                             country = flag_classes[0].replace('flag-icon-', '').upper()
#
#                     scan_data = {
#                         'timestamp': datetime.now().isoformat(),
#                         'url': url,
#                         'scan_url': scan_url,
#                         'age': cells[2].text.strip(),
#                         'size': cells[3].text.strip(),
#                         'requests': cells[4].text.strip(),
#                         'ips': cells[5].text.strip(),
#                         'threats': cells[6].text.strip(),
#                         'country': country,
#                         'status': 'locked' if row.find('img', {'alt': 'Private'}) else 'public'
#                     }
#
#                     scan_data_list.append(scan_data)
#                     self.seen_urls.add(url)
#
#                 except Exception as e:
#                     logging.error(f"Error parsing row: {e}")
#                     continue
#
#         except Exception as e:
#             logging.error(f"Error parsing HTML: {e}")
#
#         return scan_data_list
#
#     def save_results(self, results: List[Dict[str, Any]], is_verdict: bool = False):
#         """Save results to JSON file"""
#         if not results:
#             return
#
#         try:
#             output_file = self.verdicts_file if is_verdict else self.output_file
#             existing_data = []
#
#             if os.path.exists(output_file):
#                 with open(output_file, 'r', encoding='utf-8') as f:
#                     existing_data = json.load(f)
#
#             if is_verdict:
#                 # Only save malicious verdicts
#                 results = [r for r in results if r['verdict'].lower() == 'malicious']
#                 if not results:
#                     return
#
#                 # Avoid duplicates
#                 seen_urls = {item['url'] for item in existing_data}
#                 results = [r for r in results if r['url'] not in seen_urls]
#
#                 if not results:
#                     logging.info("No new malicious URLs to add")
#                     return
#
#             existing_data.extend(results)
#
#             with open(output_file, 'w', encoding='utf-8') as f:
#                 json.dump(existing_data, f, indent=2, ensure_ascii=False)
#
#             logging.info(f"Saved {len(results)} new results to {output_file}")
#
#         except Exception as e:
#             logging.error(f"Error saving results: {e}")
#
#     def restart_driver(self):
#         """Safely restart the Chrome driver"""
#         try:
#             if self.driver:
#                 self.driver.quit()
#         except Exception:
#             pass
#         time.sleep(5)
#         self.setup_driver()
#
#     def monitor_recent_scans(self, duration_minutes: int = 60, interval_seconds: int = 15):
#         """Monitor recent scans using multiprocessing"""
#         end_time = time.time() + (duration_minutes * 60)
#         num_processes = max(1, cpu_count() - 1)  # Leave one CPU core free
#
#         try:
#             with Pool(processes=num_processes) as pool:
#                 while time.time() < end_time:
#                     try:
#                         html_content = self.get_page_content()
#                         if html_content:
#                             scan_data_list = self.parse_recent_scans(html_content)
#
#                             if scan_data_list:
#                                 logging.info(f"Processing {len(scan_data_list)} scans")
#                                 results = pool.map(process_verdict, scan_data_list)
#
#                                 if results:
#                                     self.save_results(results)
#
#                                     # Check for errors
#                                     if any(r.get('verdict') == "Error" for r in results):
#                                         logging.error("Error processing verdicts")
#                                         break
#
#                                     # Save malicious results
#                                     malicious_results = [{
#                                         'url': r['url'],
#                                         'scan_url': r['scan_url'],
#                                         'verdict': r['verdict'],
#                                         'metadata': r['verdict_metadata']
#                                     } for r in results if r['verdict'].lower() == 'malicious']
#
#                                     if malicious_results:
#                                         logging.info(f"Found {len(malicious_results)} malicious URLs")
#                                         self.save_results(malicious_results, is_verdict=True)
#
#                         time.sleep(interval_seconds)
#
#                     except Exception as e:
#                         logging.error(f"Error in monitoring loop: {e}")
#                         time.sleep(interval_seconds * 2)
#
#         finally:
#             if self.driver:
#                 self.driver.quit()
#
#
# def main():
#     scraper = URLScanRecentScraper()
#     try:
#         # Monitor for 24 hours by default
#         scraper.monitor_recent_scans(duration_minutes=1440, interval_seconds=15)
#     except KeyboardInterrupt:
#         logging.info("Scraping interrupted by user")
#     except Exception as e:
#         logging.error(f"Unexpected error: {e}")
#     finally:
#         if scraper.driver:
#             scraper.driver.quit()
#
#
# if __name__ == "__main__":
#     main()
import time
import logging
import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from multiprocessing import Process, Queue, Value, Lock
import threading
from queue import Empty
import tqdm
import webdriver_utils
import verdict_processor
from stats_processor import update_statistics


def setup_logging():
    """Configure logging settings"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )


def save_results(results: List[Dict[str, Any]], output_file: str, is_verdict: bool = False):
    """Save results to appropriate JSON file"""
    if not results:
        return

    try:
        existing_data = []
        if os.path.exists(output_file):
            with open(output_file, 'r', encoding='utf-8') as f:
                existing_data = json.load(f)

        if is_verdict:
            results = [r for r in results if r['verdict'].lower() == 'malicious']
            if not results:
                return

            seen_urls = {item['url'] for item in existing_data}
            results = [r for r in results if r['url'] not in seen_urls]

            if not results:
                return

        existing_data.extend(results)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(existing_data, f, indent=2, ensure_ascii=False)

        # Update statistics if we're saving verdicts
        if is_verdict:
            stats_file = "urlscan_statistics.txt"
            results_file = "urlscan_results.json"
            update_statistics(output_file, results_file, stats_file)

    except Exception as e:
        logging.error(f"Error saving results: {str(e)}")

def process_table_row(row, base_url, seen_urls):
    """Process a single table row and return scan data if valid"""
    try:
        cells = row.find_all('td')
        if len(cells) < 7:
            return None

        url = cells[1].text.strip()
        if not url or url == "Loading..." or url in seen_urls:
            return None

        # Get scan URL
        link = cells[1].find('a')
        scan_url = None
        if link and link.get('href'):
            href = link.get('href')
            scan_url = f"{base_url}{href}" if href.startswith('/') else href
        else:
            scan_url = f"{base_url}/result/{url}"

        if not scan_url:
            return None

        return {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'scan_url': scan_url,
            'age': cells[2].text.strip(),
            'size': cells[3].text.strip(),
            'requests': cells[4].text.strip(),
            'ips': cells[5].text.strip(),
            'threats': cells[6].text.strip(),
            'status': 'locked' if row.find('img', {'alt': 'Private'}) else 'public'
        }
    except Exception as e:
        logging.error(f"Error processing row: {str(e)}")
        return None


def url_producer(url_queue: Queue, backlog_count: Value, backlog_lock: Lock, stop_flag: Value):
    """Process that continuously fetches new URLs"""
    setup_logging()
    driver = None
    seen_urls = set()
    base_url = "https://urlscan.io"

    try:
        driver = webdriver_utils.create_chrome_driver()

        while not stop_flag.value:
            try:
                # Get page content
                driver.get(base_url)
                wait = WebDriverWait(driver, 20)
                wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "table")))
                html_content = driver.page_source

                # Parse content
                soup = BeautifulSoup(html_content, 'html.parser')
                table = soup.find('table')

                if table:
                    for row in table.find_all('tr')[1:]:
                        scan_data = process_table_row(row, base_url, seen_urls)
                        if scan_data:
                            url_queue.put(scan_data)
                            seen_urls.add(scan_data['url'])
                            with backlog_lock:
                                backlog_count.value += 1

            except Exception as e:
                logging.error(f"Error in URL producer: {str(e)}")
                time.sleep(30)
                continue

            time.sleep(15)

    except Exception as e:
        logging.error(f"Fatal error in producer: {str(e)}")
    finally:
        if driver:
            driver.quit()


def verdict_consumer(url_queue: Queue, backlog_count: Value, backlog_lock: Lock,
                     stop_flag: Value, output_file: str, verdicts_file: str):
    """Process that consumes URLs and gets their verdicts"""
    setup_logging()

    while not stop_flag.value or not url_queue.empty():
        try:
            try:
                scan_data = url_queue.get(timeout=5)
            except Empty:
                continue

            # Process the verdict
            result = verdict_processor.process_verdict(scan_data)

            # Save results
            if result:
                save_results([result], output_file, is_verdict=False)
                if result.get('verdict', '').lower() == 'malicious':
                    save_results([{
                        'url': result['url'],
                        'scan_url': result['scan_url'],
                        'verdict': result['verdict'],
                        'metadata': result['verdict_metadata']
                    }], verdicts_file, is_verdict=True)

            # Update backlog count
            with backlog_lock:
                backlog_count.value -= 1

        except Exception as e:
            logging.error(f"Error in verdict consumer: {str(e)}")
            time.sleep(5)


def progress_monitor(backlog_count: Value, backlog_lock: Lock, stop_flag: Value):
    """Monitor and display progress"""
    with tqdm.tqdm(total=0, dynamic_ncols=True, desc="Backlog", unit="verdicts") as pbar:
        last_count = 0
        while not stop_flag.value:
            with backlog_lock:
                current_count = backlog_count.value
                if current_count != last_count:
                    pbar.total = max(pbar.total, current_count)
                    pbar.n = pbar.total - current_count
                    pbar.set_description(f"Backlog: {current_count}")
                    pbar.refresh()
                    last_count = current_count
            time.sleep(0.5)


def main():
    setup_logging()

    # Shared resources
    url_queue = Queue()
    backlog_count = Value('i', 0)
    backlog_lock = Lock()
    stop_flag = Value('i', 0)

    # File paths
    output_file = "urlscan_results.json"
    verdicts_file = "urlscan_verdicts.json"

    try:
        # Start producer process
        producer = Process(target=url_producer,
                           args=(url_queue, backlog_count, backlog_lock, stop_flag))
        producer.start()

        # Start consumer processes
        consumers = []
        num_consumers = 3  # Adjust based on your needs
        for _ in range(num_consumers):
            consumer = Process(target=verdict_consumer,
                               args=(url_queue, backlog_count, backlog_lock, stop_flag,
                                     output_file, verdicts_file))
            consumer.start()
            consumers.append(consumer)

        # Start progress monitor in a separate thread
        progress_thread = threading.Thread(target=progress_monitor,
                                           args=(backlog_count, backlog_lock, stop_flag))
        progress_thread.daemon = True
        progress_thread.start()

        # Run for 24 hours
        time.sleep(24 * 60 * 60)

    except KeyboardInterrupt:
        logging.info("Stopping scraper...")
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
    finally:
        # Signal processes to stop
        stop_flag.value = 1

        # Wait for processes to finish
        producer.join()
        for consumer in consumers:
            consumer.join()


if __name__ == "__main__":
    main()
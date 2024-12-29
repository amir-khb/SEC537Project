import requests
from bs4 import BeautifulSoup
import logging
from threading import Thread
import queue
import random
from typing import List, Dict, Optional
from multiprocessing import Lock


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
        sources = [
            'https://free-proxy-list.net/',
            'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=yes&anonymity=all',
            'https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps'
        ]

        for source in sources:
            try:
                response = requests.get(source, timeout=10)
                if 'free-proxy-list.net' in source:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    proxy_table = soup.find('table')
                    if proxy_table:
                        rows = proxy_table.find_all('tr')[1:]
                        for row in rows:
                            cols = row.find_all('td')
                            if len(cols) >= 7 and cols[6].text.strip() == 'yes':
                                ip, port = cols[0].text.strip(), cols[1].text.strip()
                                proxies.append({
                                    'http': f'http://{ip}:{port}',
                                    'https': f'http://{ip}:{port}'
                                })
                elif 'proxyscrape.com' in source:
                    for line in response.text.split('\n'):
                        if ':' in line:
                            ip, port = line.strip().split(':')
                            proxies.append({
                                'http': f'http://{ip}:{port}',
                                'https': f'http://{ip}:{port}'
                            })
                elif 'geonode.com' in source:
                    data = response.json()
                    for proxy in data.get('data', []):
                        ip, port = proxy.get('ip'), proxy.get('port')
                        if ip and port:
                            proxies.append({
                                'http': f'http://{ip}:{port}',
                                'https': f'https://{ip}:{port}'
                            })
            except Exception as e:
                logging.error(f"Error fetching from {source}: {e}")

        return proxies

    def validate_proxy(self, proxy: Dict) -> bool:
        """Validate a single proxy"""
        test_urls = ['https://www.google.com', 'https://www.cloudflare.com', 'https://www.amazon.com']
        try:
            response = requests.get(
                random.choice(test_urls),
                proxies=proxy,
                timeout=5,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}
            )
            return response.status_code == 200
        except Exception:
            return False

    def validate_proxies(self, proxies: List[Dict]) -> List[Dict]:
        """Validate multiple proxies using threading"""
        proxy_queue = queue.Queue()
        valid_proxies = []

        for proxy in proxies:
            proxy_queue.put(proxy)

        def worker():
            while True:
                try:
                    proxy = proxy_queue.get_nowait()
                except queue.Empty:
                    break

                if self.validate_proxy(proxy):
                    with self.proxy_lock:
                        if len(valid_proxies) < self.max_proxies:
                            valid_proxies.append(proxy)
                            logging.info(f"Found working proxy: {proxy}")
                proxy_queue.task_done()

        threads = []
        num_threads = min(20, len(proxies))
        for _ in range(num_threads):
            t = Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)

        proxy_queue.join()
        for t in threads:
            t.join()

        return valid_proxies[:self.max_proxies]

    def get_working_proxy(self) -> Optional[Dict]:
        """Get a random working proxy"""
        if not self.working_proxies:
            logging.info("Fetching and validating new proxies...")
            proxies = self.fetch_free_proxies()
            self.working_proxies = self.validate_proxies(proxies)

        return random.choice(self.working_proxies) if self.working_proxies else None

    def refresh_proxies(self):
        """Refresh the proxy pool"""
        logging.info("Refreshing proxy pool...")
        proxies = self.fetch_free_proxies()
        self.working_proxies = self.validate_proxies(proxies)
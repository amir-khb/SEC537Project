from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from proxy_handler import ProxyHandler


def create_chrome_driver(use_proxy: bool = False) -> webdriver.Chrome:
    """Create and configure a Chrome WebDriver instance"""
    chrome_options = Options()
    chrome_options.add_argument('--headless=new')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--window-size=1920,1080')
    chrome_options.add_argument('--disable-notifications')
    chrome_options.add_argument('--disable-popup-blocking')

    if use_proxy:
        proxy_handler = ProxyHandler(max_proxies=1)
        proxy = proxy_handler.get_working_proxy()
        if proxy:
            proxy_server = proxy['https']
            chrome_options.add_argument(f'--proxy-server={proxy_server}')

    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'
    chrome_options.add_argument(f'user-agent={user_agent}')

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)
    driver.set_page_load_timeout(30)

    return driver
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from urllib.parse import urljoin

class Scanner:
    def __init__(self, url):
        self.target_url = url
        self.target_links = []


    def extract_links_from(self, url):
        response = requests.get(url)
        return re.findall('(?:href=")(.*?)"', response.content.decode('ISO-8859-1'))

    def crawl(self, url=None):
        if url == None:
            url = self.target_url
        href_link = self.extract_links_from(url)
        for link in href_link:
            link = urljoin(url, link)

            if self.target_url in link and link not in self.target_links:
                self.target_links.append(link)
                print(link)
                self.crawl(link)



target_url = "http://google.com/"
vuln_scanner = Scanner(target_url)
vuln_scanner.crawl()

import re
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


class Scanner:
    def __init__(self, url, ignore_links, payload_file_path):
        self.session = requests.Session()
        self.target_url = url
        self.target_links = []
        self.logout_link_remove = ignore_links
        self.payload_file_path = payload_file_path

    def extract_links_from(self, url):
        response = self.session.get(url)
        return re.findall('(?:href=")(.*?)"', response.content.decode('ISO-8859-1'))

    def crawl(self, url=None):
        if url is None:
            url = self.target_url
        href_link = self.extract_links_from(url)
        for link in href_link:
            link = urljoin(url, link)

            if self.target_url in link and link not in self.target_links and link not in self.logout_link_remove:
                self.target_links.append(link)
                print(link)
                self.crawl(link)

    def extract_forms(self, url):
        response = self.session.get(url)
        sorted_html = BeautifulSoup(response.content, "html.parser")
        return sorted_html.findAll("form")

    def submit_form(self, form, value, url):
        action = form.get("action")
        post_url = urljoin(url, action)
        method = form.get("method")

        input_list = form.findAll("input_field")
        post_data = {}
        for input_field in input_list:
            input_name = input_field.get("name")
            input_type = input_field.get("type")
            input_value = input_field.get("value")
            if input_type == "text":
                input_value = value

            post_data[input_name] = input_value
        if method == "post":
            return self.session.post(post_url, data=post_data)
        return self.session.get(post_url, params=post_data)

    def read_file(self):
        """
        Reads all payloads in a text file separated by a new line "\n"
        Uses the file path defined in the [self.__init__] method
        :return: List<String> of payloads input
        """
        with open(self.payload_file_path, 'r') as file:
            return file.readlines()

    def run_scanner(self):
        for link in self.target_links:
            forms = self.extract_forms(link)
            payloads = self.read_file()
            for form in forms:
                print(" Testing Started " + link)
                for payload in payloads:
                    is_vulnerable_to_xss = self.test_xss_in_form(form, link, payload)
                    if is_vulnerable_to_xss:
                        print("XSS Found in  " + link + "In the following form")
                        print(form)

            if "=" in link:
                print("Testing for " + link)
                for payload in payloads:
                    is_vulnerable_to_xss = self.test_xss_in_link(link, payload)
                    if is_vulnerable_to_xss:
                        print("XSS Found in link " + link)

    def test_xss_in_link(self, url, payload):
        url = url.replace("=", "=" + payload)
        response = self.session.get(url)
        return payload in str(response.content)

    def test_xss_in_form(self, form, url, payload):
        response = self.submit_form(form, payload, url)
        if payload in str(response.content):
            return payload in response.content


if __name__ == '__main__':
    target_url = "http://192.168.1.104/dvwa/"
    logout_link_remove = [target_url + "logout.php"]
    credentials = {"username": "admin", "password": "admin", "Login": "submit"}

    vuln_scanner = Scanner(target_url, logout_link_remove, "path to txt file here")
    vuln_scanner.session.post(target_url + "/" + "login.php", data=credentials)

    vuln_scanner.crawl()
    vuln_scanner.run_scanner()

import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from urllib.parse import urljoin
class Scanner:
    def _init_(self, url, logout_link_ignore):
        self.session = requests.Session()
        self.WebSiteURL = url
        self.target_links = []
        self.link_for_logout = link_for_logout
    def extract_links_form(self, url): 
        response = self.session.get(url)
        return re.findall('(?:href=")(.*?)"', response.content.decode('ISO-8859-1'))
    def crawl(self, url):
        href_links = self.extract_links_form(url)
        for link in href_links:
            link = urljoin(url, link)
            if self.WebSiteURL in link and link not in self.target_links and link not in self.link_for_logout :
                self.target_links.append(link)
                print(link)
                self.crawl(link) 
    def extract_forms(self, url):
        response = self.session.get(url)
        parsed_html = BeautifulSoup(response.content, "html.parser")
        return parsed_html.findAll("form")
    def submit_form(self, form, value, url):
        action = form.get("action")
        post_url = urljoin(url, action)
        method = form.get("method")
        input_list = form.findAll("input")
        post_data = {}
        for input in input_list:
            input_name = input.get("name")
            input_type = input.get("type")
            input_value = input.get("value")
            if input_type == "text":
                input_value = value
            post_data[input_name] = input_value
        if method == "post":
            return self.session.post(post_url, data=post_data)
        return self.session.get(post_url, params=post_data)-
    def run_scanner(self):
        for link in self.target_links:
            forms = self.extract_forms(link)
            for form in forms:
                print("\n\nXSS for form:    " + link)
                is_vulnerable_to_xss = self.test_xss_in_form(form, link)
                if is_vulnerable_to_xss:
                    print("XSS Found in given form:    " + link)
                    #print(form)
            if "=" in link:
                print("\n\n--> finding For XSS vulnerability   " + link)
                is_vulnerable_to_xss = self.test_xss_in_link(link)
    def test_xss_in_link(self, WebSiteURL):
        with open("xss") as f:
            for line in f:
                #print(line)
                url = WebSiteURL
                xss_test = line
                #url = url.replace("=" , "=" + xss_test)
                url_rem = url.split('=')[0]
                final_url = url_rem + "=" + xss_test
                response = self.session.get(final_url)
                is_present = xss_test in str(response.text)
                if is_present is True:
                    print("XSS Found in link " + final_url)
                    print(xss_test)
                    return is_present
            return False
    def test_xss_in_form(self, form, WebSiteURL):
        with open("XSS_payloads.txt") as f:
            for line in f:
                url = WebSiteURL
                xss_test = line
                #xss_test = "<script>alert(1)</script>"
                response = self.submit_form(form, xss_test, url)
                if xss_test in str(response.text):
                    print(xss_test)
                    return True
            return False
WebSiteURL = input("Enter The URL --->   ")
link_for_logout = (WebSiteURL + "logout")
username_value = input("Please input Username : ") 
password_value = input("Plesse input Password : ") 
credentials ={'username': username_value , 'password' : password_value , 'submit': 'LOG IN'}
#credentials ={'username': username_value , 'password' : password_value , 'Login': 'submit'}
#credentials = {"username": "gordonb", "password": "abc123", "Login": "submit"}
xss_scanner = Scanner(WebSiteURL, link_for_logout)
xss_scanner.session.post(WebSiteURL + "/" + "login", data=credentials)
#xss_scanner.session.post(WebSiteURL, data=credentials)
xss_scanner.crawl(WebSiteURL)
xss_scanner.run_scanner()
#testApps
#http://192.168.1.101/dvwa    gordonb:abc123
#http://testphp.vulnweb.com   test:test
#https://54-177-109-222-bank.vulnerablesites.net/ShadowBank/    sunil:sunil

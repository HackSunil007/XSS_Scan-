import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from urllib.parse import urljoin
class Scanner:
    def __init__(self, url, logout_link_ignore):
        self.session = requests.Session()
        self.target_url = url
        self.target_links = []
        self.logout_link_ignore = logout_link_ignore


    def extract_links_form(self, url): 
        response = self.session.get(url)
        return re.findall('(?:href=")(.*?)"', response.content.decode('ISO-8859-1'))


    def crawl(self, url):
        href_links = self.extract_links_form(url)
        for link in href_links:
            link = urljoin(url, link)
            if self.target_url in link and link not in self.target_links and link not in self.logout_link_ignore :
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
                print("\n\nTest For XSS in Forms:    " + link)
                is_vulnerable_to_xss = self.test_xss_in_form(form, link)
                if is_vulnerable_to_xss:
                    print("XSS Found in form:    " + link)
                    #print(form)
            if "=" in link:
                print("\n\n--> Testing For XSS   " + link)
                is_vulnerable_to_xss = self.test_xss_in_link(link)


    def test_xss_in_link(self, target_url):
        with open("XSS_payloads.txt") as f:
            for line in f:
                #print(line)
                url = target_url
                xss_test_script = line
                #url = url.replace("=" , "=" + xss_test_script)
                url_rem = url.split('=')[0]
                final_url = url_rem + "=" + xss_test_script
                response = self.session.get(final_url)
                is_present = xss_test_script in str(response.text)
                if is_present is True:
                    print("XSS Found in link " + final_url)
                    print(xss_test_script)
                    return is_present
            return False


    def test_xss_in_form(self, form, target_url):
        with open("XSS_payloads.txt") as f:
            
            for line in f:
                url = target_url
                xss_test_script = line
                #xss_test_script = "<script>alert(1)</script>"
                response = self.submit_form(form, xss_test_script, url)
                if xss_test_script in str(response.text):
                    print(xss_test_script)
                    return True
            return False

target_url = input("Enter The URL --->   ")
logout_link_ignore = (target_url + "logout")
username_value = input("Please input Username : ") 
password_value = input("Plesse input Password : ") 
credentials ={'username': username_value , 'password' : password_value , 'submit': 'LOG IN'}
#credentials ={'username': username_value , 'password' : password_value , 'Login': 'submit'}
#credentials = {"username": "gordonb", "password": "abc123", "Login": "submit"}
xss_scanner = Scanner(target_url, logout_link_ignore)
xss_scanner.session.post(target_url + "/" + "login", data=credentials)
#xss_scanner.session.post(target_url, data=credentials)
xss_scanner.crawl(target_url)
xss_scanner.run_scanner()
#testApps
#http://192.168.1.101/dvwa    gordonb:abc123
#http://testphp.vulnweb.com   test:test
#https://54-177-109-222-bank.vulnerablesites.net/ShadowBank/    sunil:sunil

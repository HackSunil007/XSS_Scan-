import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from urllib.parse import urljoin

class Scanner:
	def __init__(self, url):
		self.session = requests.Session()
		self.target_url = url
		self.target_links = []
		#self.logout_link_ignore = logout_link_ignore

	def extract_links_form(self, url): 
		response = self.session.get(url)
		return re.findall('(?:href=")(.*?)"', response.content.decode('ISO-8859-1'))

	def crawl(self, url):
		href_links = self.extract_links_form(url)
		for link in href_links:
			link = urljoin(url, link)
			if self.target_url in link and link not in self.target_links:
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
		return self.session.get(post_url, params=post_data)

	# SQL Injection Scanner...
	def run_scanner_sqli(self):
		for link in self.target_links:
			forms = self.extract_forms(link)
			for form in forms:
				print("Testing For SQLi in a form: " + link)
				is_vulnerable_to_xss = self.test_sqli_in_form(form, link)
				if is_vulnerable_to_xss:
					print("SQLi Found in form: " + link)
			if "=" in link:
				print("Testing For SQLi in a link: " + link)
				is_vulnerable_to_xss = self.test_sqli_in_link(link)

	def test_sqli_in_link(self, target_url):
		with open("SQLi_payloads.txt") as f:
			for line in f:
				url = target_url
				sqli_test_script = line
				url_rem = url.split('=')[0]
				final_url = url_rem + "=" + sqli_test_script
				response = self.session.get(final_url)

				all_headers = response.request.headers
				for key, value in all_headers.items():
					value = value + line
					new_header = {key:value}
					self.test_sqli_in_header(target_url, new_header)

				is_present = "error in your SQL syntax" in str(response.text)
				if is_present is True:
					print("SQLi Found in link: " + final_url)
					print("Payload used: " + sqli_test_script)
					return is_present
			return False

	def test_sqli_in_form(self, form, target_url):
		with open("SQLi_payloads.txt") as f:
			
			for line in f:
				url = target_url
				sqli_test_script = line
				response = self.submit_form(form, sqli_test_script, url)
				if "error in your SQL syntax" in str(response.text):
					print("Payload used: " + sqli_test_script)
					return True
			return False

	def test_sqli_in_header(self, target_url, new_header):
		response = self.session.get(target_url)
		is_present = "error in your SQL syntax" in str(response.text)
		if is_present is True:
					print("SQLi Found in link: " + target_url + " using header: " + new_header)

	# Cross-Site Scripting Scanner...
	def run_scanner_xss(self):
		for link in self.target_links:
			forms = self.extract_forms(link)
			for form in forms:
				print("Testing For XSS in Forms: " + link)
				is_vulnerable_to_xss = self.test_xss_in_form(form, link)
				if is_vulnerable_to_xss:
					print("XSS Found in form: " + link)
			if "=" in link:
				print("Testing For XSS: " + link)
				is_vulnerable_to_xss = self.test_xss_in_link(link)

	def test_xss_in_link(self, target_url):
		with open("XSS_payloads.txt") as f:
			for line in f:
				url = target_url
				xss_test_script = line
				url_rem = url.split('=')[0]
				final_url = url_rem + "=" + xss_test_script
				response = self.session.get(final_url)
				is_present = xss_test_script in str(response.text)
				if is_present is True:
					print("XSS Found in link " , final_url)
					print("Payload used: " , xss_test_script)
					return is_present
			return False

	def test_xss_in_form(self, form, target_url):
		with open("XSS_payloads.txt") as f:
			
			for line in f:
				url = target_url
				xss_test_script = line
				response = self.submit_form(form, xss_test_script, url)
				if xss_test_script in str(response.text):
					print("Payload used: " + xss_test_script)
					return True
			return False


def main():
	target_url = input("Enter The URL to scan: ")
	scope = input('Which vulnerability do you want to scan? (XSS/SQLi/All): ').lower()

	scanner = Scanner(target_url)
	scanner.crawl(target_url)

	if (scope == "all"):
		scanner.run_scanner_sqli()
		scanner.run_scanner_xss()
	elif (scope == "xss"):
		scanner.run_scanner_xss()
	elif (scope == "sqli"):
		scanner.run_scanner_sqli()
	else:
		print('Wrong choice. Please try again...')
		main()

if __name__=='__main__':
	main()

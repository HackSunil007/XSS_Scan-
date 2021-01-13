Automated scanner for SQLi and XSS

STEPS 

1. Provide input as a URL
2. Crawl all the pages (GET and POST too)
3. Look for the reflection parameters in the html rrespose
4. Then i will provide one payload.txt file which contans the payload list.
5. Read line by line from the payload.txt file and pass to the each URL end point like URL http://abc.com?id=1* (replace * with payload)
6. If our provided payload is reflected in the response then print that reflected form and show message like "Vulnerable to XSS and SQLi"

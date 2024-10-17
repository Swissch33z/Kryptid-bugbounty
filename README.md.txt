
# Kryptid Hunter

Kryptid Hunter is an advanced bug hunting tool designed for security researchers and penetration testers. This tool includes various scanners for common vulnerabilities found in web applications, such as Local File Inclusion (LFI), SQL Injection (SQLi), Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), Server-Side Request Forgery (SSRF), and Insecure Direct Object References (IDOR). Additionally, it provides functionality for data export requests and a fun feature to retrieve a random cat photo.

## Features

- **LFI Scanner**: Tests for Local File Inclusion vulnerabilities.
- **SQLi Scanner**: Checks for SQL Injection vulnerabilities.
- **XSS Scanner**: Identifies Cross-Site Scripting vulnerabilities.
- **CSRF Detector**: Detects potential Cross-Site Request Forgery vulnerabilities.
- **SSRF Scanner**: Scans for Server-Side Request Forgery vulnerabilities.
- **IDOR Scanner**: Placeholder for Insecure Direct Object Reference testing (to be implemented).
- **Data Export Request**: Allows users to make GET requests for data export testing.
- **Cat Photo Retrieval**: Fetches a random cat photo for a fun user experience.

## Requirements

- Python 3.x
- Required Python libraries:
  - `requests`
  - `PIL` (Pillow)

You can install the required libraries using pip:

```bash
pip install requests Pillow
```

## Usage

1. Clone this repository or download the script file.
2. Run the script using Python:
   ```bash
   python kryptid_hunter.py
   ```
3. Follow the on-screen menu to select the desired scanner or feature.

## Logging

All vulnerabilities detected during the scans are logged in a file named `vulnerability_log.txt`. Additionally, all actions and errors are logged in a separate log file named with a timestamp, such as `kryptid_hunter_YYYYMMDD_HHMMSS.log`.

## Contributing

Contributions to the project are welcome. If you would like to contribute, please fork the repository and submit a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.

## Author

Made by ig0r

## Disclaimer

This tool is intended for educational purposes and authorized penetration testing only. Use it responsibly and ensure you have permission to test any application you scan.

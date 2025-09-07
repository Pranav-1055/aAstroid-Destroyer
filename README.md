# Astroid Destroyer

Astroid Destroyer is a lightweight and powerful security testing tool designed to detect Cross-Site Scripting (XSS) vulnerabilities in web applications.  
It can scan both GET and POST parameters, test with built-in or custom payloads, and identify reflected and DOM-based XSS issues.  

With features like multi-threading, proxy support, detailed verbose logging, and JSON report generation, Astroid Destroyer combines speed and simplicity, making it a practical tool for:  
- Security researchers  
- Penetration testers  
- Web developers  

---

## Features

- Detects reflected and DOM-based XSS vulnerabilities  
- GET and POST parameter scanning  
- Support for custom payloads from file (`--payloads`)  
- Multi-threaded scanning for faster results  
- Proxy support (Burp Suite / OWASP ZAP)  
- Custom headers and cookies  
- Verbose logging for debugging  
- JSON report output for structured results  
- Lightweight and easy to run on any system  

  Install required dependencies:

pip install requests

Usage
Basic Scan
python dsxs_plus.py -u "http://example.com/page.php?id=1"


Scans the id parameter in the URL using default payloads.

Scan with POST Data
python dsxs_plus.py -u "http://example.com/login.php" --data "username=test&password=123"


Tests for XSS in POST parameters (such as login forms).

Use Custom Payload File
python dsxs_plus.py -u "http://example.com/page.php?id=1" --payloads payloads.txt


Loads payloads from payloads.txt.

Example payloads.txt:

"><svg/onload=alert(1337)>
<script>alert('XSS')</script>
'"><img src=x onerror=alert(1)>

Custom Headers

Custom User-Agent:

python dsxs_plus.py -u "http://example.com" --ua "Mozilla/5.0 Scanner"


Add Cookies (for authenticated pages):

python dsxs_plus.py -u "http://example.com/profile.php?id=5" --cookie "PHPSESSID=abc123"

Proxy Support
python dsxs_plus.py -u "http://example.com" --proxy "http://127.0.0.1:8080"


Routes requests through a proxy such as Burp Suite or OWASP ZAP.

Save Report to JSON
python dsxs_plus.py -u "http://example.com/page.php?id=1" --report result.json


Creates a result.json file with detailed findings.

Verbose Mode
python dsxs_plus.py -u "http://example.com" -v


Prints detailed scanning steps to the console.

Performance Options

Increase timeout (default 15s):

python dsxs_plus.py -u "http://example.com" --timeout 30


Retry failed requests (default 1):

python dsxs_plus.py -u "http://example.com" --retries 3


Increase threads (default 6):

python dsxs_plus.py -u "http://example.com" --threads 10

Example Output

Command:

python dsxs_plus.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -v


Output:

 (i) page may contain DOM sinks
 * scanning GET parameter 'cat'
  (!) possible XSS in 'cat' with payload: <img src=x onerror=alert(1)>

Scan completed in 2.43s — 1 issue(s) found
 - GET param 'cat' -> payload: <img src=x onerror=alert(1)>
   evidence: ...<img src=x onerror=alert(1)>...

JSON Report Example

If you run with --report report.json, the output will be structured as follows:

{
  "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
  "vulns": [
    {
      "param": "cat",
      "method": "GET",
      "payload": "<img src=x onerror=alert(1)>",
      "evidence": "...<img src=x onerror=alert(1)>..."
    }
  ],
  "dom_like": true
}

Quick Reference
Option	Description
-u URL	Target URL (required)
--data	POST data (e.g., a=1&b=2)
--payloads	Load payloads from file
--ua	Custom User-Agent
--cookie	Add Cookie header
--proxy	Send traffic via proxy
--timeout	Request timeout (default 15s)
--retries	Retry requests (default 1)
--threads	Number of threads (default 6)
--report	Save JSON report
-v	Verbose mode
Disclaimer

This tool is intended for educational and authorized security testing only.
Do not use it against systems you do not own or have explicit permission to test.
The author and contributors are not responsible for misuse or illegal activity.

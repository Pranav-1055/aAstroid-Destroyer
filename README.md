# Astroid Destroyer

Astroid Destroyer is a lightweight and powerful security testing tool designed to detect Cross-Site Scripting (XSS) vulnerabilities in web applications.  
It can scan both GET and POST parameters, test with built-in or custom payloads, and identify reflected and DOM-based XSS issues.  

With features like multi-threading, proxy support, detailed verbose logging, timeout and retry options, prefix/suffix payload markers, custom headers, and JSON report generation, Astroid Destroyer combines speed and simplicity.

---

## Features

- Detects reflected XSS vulnerabilities in GET and POST parameters  
- Detects potential DOM-based XSS issues by analyzing scripts and sinks (`innerHTML`, `eval`, `document.write`, etc.)  
- Supports custom payloads from a file (`--payloads`)  
- Automatic prefix/suffix markers to improve detection and reduce false negatives  
- Multi-threaded scanning for faster results  
- Retry failed requests and set custom timeouts (`--retries`, `--timeout`)  
- Proxy support (Burp Suite / OWASP ZAP integration)  
- Custom headers: User-Agent, Cookie, Referer  
- Verbose/debug mode to trace scanning steps (`-v`)  
- JSON report output for structured results (`--report`)  
- Lightweight and easy to run on any system  

---

## Installation

```bash
git clone https://github.com/yourusername/astroid-destroyer.git
cd astroid-destroyer
pip install -r requirements.txt
```

---

## Usage

### Basic Scan
```bash
python astroid_destroyer.py -u "http://example.com/index.php?q=test"
```

### Scan with POST Data
```bash
python astroid_destroyer.py -u "http://example.com/login.php" --data "username=admin&password=123"
```

### Use Custom Payload File
```bash
python astroid_destroyer.py -u "http://example.com/" --payloads payloads.txt
```

### Set Custom Headers
```bash
python astroid_destroyer.py -u "http://example.com/" --ua "CustomUserAgent" --cookie "PHPSESSID=abc123" --referer "http://referrer.com"
```

### Proxy Support
```bash
python astroid_destroyer.py -u "http://example.com/" --proxy "http://127.0.0.1:8080"
```

### Verbose Mode (Debugging)
```bash
python astroid_destroyer.py -u "http://example.com/" -v
```

### Save Results to JSON
```bash
python astroid_destroyer.py -u "http://example.com/" --report results.json
```

### Timeout and Retries
```bash
python astroid_destroyer.py -u "http://example.com/" --timeout 30 --retries 3
```

### Multi-threaded Scanning
```bash
python astroid_destroyer.py -u "http://example.com/" --threads 10
```

---

## Example

Command:
```bash
python astroid_destroyer.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -v
```

Output:
```
* scanning GET parameter 'cat'
  [+] Trying payload: '"><svg/onload=alert(1337)>
  [!] Match found -> possible XSS
Scan completed — 1 issue(s) found
```

JSON Report Example:
```json
{
  "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
  "vulns": [
    {
      "param": "cat",
      "method": "GET",
      "payload": "<svg/onload=alert(1337)>",
      "evidence": "...<svg/onload=alert(1337)>..."
    }
  ],
  "dom_like": true
}
```

---

## Disclaimer

Astroid Destroyer is created for educational purposes and authorized security testing only.  
Do not use this tool on systems without explicit permission.  
The author is not responsible for any misuse or damage caused.

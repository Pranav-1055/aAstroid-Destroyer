#!/usr/bin/env python3
"""
DSXS+ — Damn Small XSS Scanner (clean version, with external payloads)
"""

import argparse
import json
import random
import re
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

try:
    import requests
    from requests.adapters import HTTPAdapter, Retry
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

# -------------------------------------------------
# Configuration
# -------------------------------------------------
NAME, VERSION = "DSXS+", "1.1"
DEFAULT_TIMEOUT = 15
DEFAULT_THREADS = 6
PREFIX_SUFFIX_LENGTH = 6

# Default payloads (used if no file is provided)
DEFAULT_PAYLOADS = [
    "XXP{pfx}<>{sfx}",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "';alert(1);//",
    "<svg/onload=alert(1)>",
]

DOM_SINKS = [
    r"document\.write\(",
    r"\.innerHTML",
    r"\.outerHTML",
    r"eval\(",
    r"location\.(href|search)",
    r"window\.location",
]

DOM_FILTER = re.compile(r"(?s)<!--.*?-->|\"[^\"]*\"|'[^']*'")

# -------------------------------------------------
# HTTP Handling
# -------------------------------------------------
def build_session(timeout, retries, headers, proxy):
    s = requests.Session()
    if retries > 0:
        retry = Retry(
            total=retries,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        s.mount("http://", HTTPAdapter(max_retries=retry))
        s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update(headers or {})
    if proxy:
        s.proxies.update({"http": proxy, "https": proxy})
    s.request_timeout = timeout
    return s

def fetch(session, method, url, data=None):
    try:
        if method == "GET":
            r = session.get(url, timeout=session.request_timeout)
        else:
            r = session.post(url, data=data, timeout=session.request_timeout)
        return r.status_code, r.text or ""
    except Exception as e:
        return None, str(e)

# -------------------------------------------------
# Utilities
# -------------------------------------------------
def markerize(payload):
    pfx = "".join(random.sample(string.ascii_lowercase, PREFIX_SUFFIX_LENGTH))
    sfx = "".join(random.sample(string.ascii_lowercase, PREFIX_SUFFIX_LENGTH))
    return payload.replace("{pfx}", pfx).replace("{sfx}", sfx), pfx, sfx

def has_dom_sinks(body):
    stripped = re.sub(DOM_FILTER, "", body or "")
    return any(re.search(rx, stripped, re.I) for rx in DOM_SINKS)

def inject_url(url, param, value):
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    params = [(k, value if k == param else v) for k, v in params]
    return urlunparse(parsed._replace(query=urlencode(params)))

def inject_data(data_str, param, value):
    params = parse_qsl(data_str or "", keep_blank_values=True)
    params = [(k, value if k == param else v) for k, v in params]
    return urlencode(params)

def extract_params(url, data):
    params = []
    if url and "?" in url:
        params.extend(parse_qsl(urlparse(url).query, keep_blank_values=True))
    if data:
        params.extend(parse_qsl(data, keep_blank_values=True))
    return list({k for k, _ in params})

def load_payloads(file_path):
    """Load payloads from a file (one per line), ignore comments/empty lines"""
    try:
        with open(file_path, "r", encoding="utf8") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            ]
    except Exception as e:
        print(f"[!] Failed to load payloads from {file_path}: {e}")
        return DEFAULT_PAYLOADS

# -------------------------------------------------
# Scanner
# -------------------------------------------------
def scan_param(session, url, data, param, method, payloads, verbose=False):
    findings = []
    if verbose:
        print(f" * scanning {method} parameter '{param}'")

    for payload in payloads:
        marked, pfx, sfx = markerize(payload)

        if method == "GET":
            target = inject_url(url, param, marked)
            _, body = fetch(session, "GET", target)
        else:
            new_data = inject_data(data, param, marked)
            _, body = fetch(session, "POST", url, new_data)

        if pfx in body and sfx in body:
            context = body[max(body.find(pfx) - 40, 0): body.find(sfx) + 40]
            findings.append({
                "param": param,
                "method": method,
                "payload": payload,
                "evidence": context.strip()[:200],
            })
            if verbose:
                print(f"  (!) possible XSS in '{param}' with payload: {payload}")
    return findings

def scan_page(session, url, data, payloads, threads, verbose=False):
    results = {"url": url, "vulns": [], "dom_like": False}

    # Check DOM sinks
    _, body = fetch(session, "GET", url)
    if body and has_dom_sinks(body):
        results["dom_like"] = True
        if verbose:
            print(" (i) page may contain DOM sinks")

    params = extract_params(url, data)
    if not params:
        if verbose:
            print(" (x) no parameters found")
        return results

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = []
        for p in params:
            futures.append(pool.submit(scan_param, session, url, data, p, "GET", payloads, verbose))
            futures.append(pool.submit(scan_param, session, url, data, p, "POST", payloads, verbose))
        for f in as_completed(futures):
            results["vulns"].extend(f.result())
    return results

# -------------------------------------------------
# Main
# -------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description=f"{NAME} v{VERSION}")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--data", help="POST data (a=1&b=2)")
    parser.add_argument("--payloads", help="File with payloads (one per line)")
    parser.add_argument("--ua", help="Custom User-Agent")
    parser.add_argument("--cookie", help="Custom Cookie header")
    parser.add_argument("--proxy", help="HTTP proxy (http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    parser.add_argument("--report", help="Write JSON report to file")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    headers = {"User-Agent": args.ua or NAME}
    if args.cookie:
        headers["Cookie"] = args.cookie

    session = build_session(args.timeout, args.retries, headers, args.proxy)

    payloads = load_payloads(args.payloads) if args.payloads else DEFAULT_PAYLOADS

    start = time.time()
    results = scan_page(session, args.url, args.data, payloads, args.threads, args.verbose)
    duration = time.time() - start

    # Summary
    found = len(results["vulns"])
    print(f"\nScan completed in {duration:.2f}s — {found} issue(s) found")
    for v in results["vulns"]:
        print(f" - {v['method']} param '{v['param']}' -> payload: {v['payload']}")
        print(f"   evidence: {v['evidence']}\n")

    if args.report:
        with open(args.report, "w", encoding="utf8") as f:
            json.dump(results, f, indent=2)
        print("Report saved to", args.report)

if __name__ == "__main__":
    main()

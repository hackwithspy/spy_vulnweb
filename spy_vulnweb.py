#!/usr/bin/env python3
"""
SPY-VULNWEB v1.0
Kali Linux-only, non-destructive security assessment tool.

Use only on websites you own or have explicit permission to test.
"""

import os
import sys
import json
import ssl
import socket
import argparse
import platform
import threading
import webbrowser
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


VERSION = "1.0"
APP = "SPY-VULNWEB"
TIMEOUT = 5

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143,
    443, 445, 3306, 3389, 5432, 8080, 8443
]

HEADERS_TO_CHECK = {
    "Content-Security-Policy": "Helps prevent content injection",
    "Strict-Transport-Security": "Enforces HTTPS",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "X-Frame-Options": "Helps prevent clickjacking",
    "Referrer-Policy": "Controls referrer information",
    "Permissions-Policy": "Restricts browser features"
}

FINDINGS = []
TARGET = ""
LOCK = threading.Lock()


# ---------------- KALI LINUX CHECK ----------------

def check_kali():
    if not sys.platform.startswith("linux"):
        print("[!] SPY-VULNWEB works only on Kali Linux.")
        sys.exit(1)

    try:
        with open("/etc/os-release") as f:
            data = f.read().lower()

        if 'id=kali' not in data:
            print("[!] Unsupported operating system.")
            print("[!] This tool is restricted to Kali Linux.")
            sys.exit(1)

    except OSError:
        print("[!] Cannot verify Kali Linux.")
        sys.exit(1)


# ---------------- TERMINAL BANNER ----------------

def banner():
    os.system("clear")
    print(r"""
███████╗██████╗ ██╗   ██╗
██╔════╝██╔══██╗╚██╗ ██╔╝
███████╗██████╔╝ ╚████╔╝
╚════██║██╔═══╝   ╚██╔╝
███████║██║        ██║
╚══════╝╚═╝        ╚═╝

██╗   ██╗██╗   ██╗██╗     ███╗   ██╗
██║   ██║██║   ██║██║     ████╗  ██║
╚██╗ ██╔╝██║   ██║██║     ██╔██╗ ██║
 ╚████╔╝ ╚██████╔╝███████╗██║╚██╗██║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝ ╚══╝╚═╝

       SPY-VULNWEB v1.0
   AUTOMATED SECURITY SCANNER
   --------------------------
   Kali Linux Exclusive
   Authorized Testing Only
""")

# ---------------- FINDING MANAGEMENT ----------------

def add_finding(name, severity, details, evidence=""):
    with LOCK:
        FINDINGS.append({
            "name": name,
            "severity": severity,
            "details": details,
            "evidence": evidence,
            "time": datetime.now(timezone.utc).isoformat()
        })


def severity_counts():
    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }

    for item in FINDINGS:
        if item["severity"] in counts:
            counts[item["severity"]] += 1

    return counts


# ---------------- HTML FORM PARSER ----------------

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag == "form":
            self.current = {
                "method": attrs.get("method", "get").lower(),
                "action": attrs.get("action", "")
            }
            self.forms.append(self.current)

        elif tag == "input" and self.current is not None:
            self.current.setdefault("inputs", []).append({
                "name": attrs.get("name", ""),
                "type": attrs.get("type", "text")
            })

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


# ---------------- TARGET VALIDATION ----------------

def normalize_target(target):
    target = target.strip()

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    parsed = urlparse(target)

    if not parsed.hostname:
        raise ValueError("Invalid target URL")

    if parsed.username or parsed.password:
        raise ValueError("Credentials in URLs are not accepted")

    return target


# ---------------- HTTP SECURITY SCAN ----------------

def scan_http(url):
    print("\n[+] HTTP security assessment")

    try:
        response = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "SPY-VULNWEB/1.0"},
            verify=True
        )

        headers = response.headers

        print("[+] HTTP status:", response.status_code)

        # HTTPS enforcement
        if urlparse(response.url).scheme != "https":
            add_finding(
                "HTTPS Not Enforced",
                "High",
                "The final website URL does not use HTTPS."
            )

        # Security headers
        for header, explanation in HEADERS_TO_CHECK.items():
            if header not in headers:
                severity = (
                    "High" if header ==
                    "Content-Security-Policy" else "Medium"
                )

                add_finding(
                    "Missing Security Header",
                    severity,
                    header + ": " + explanation
                )

        # Server disclosure
        if headers.get("Server"):
            add_finding(
                "Server Information Disclosure",
                "Low",
                "Server header reveals server information.",
                headers.get("Server", "")
            )

        if headers.get("X-Powered-By"):
            add_finding(
                "Technology Information Disclosure",
                "Low",
                "X-Powered-By exposes technology information.",
                headers.get("X-Powered-By", "")
            )

        # CORS configuration
        cors = headers.get("Access-Control-Allow-Origin")

        if cors == "*":
            add_finding(
                "Permissive CORS Configuration",
                "Medium",
                "CORS allows every origin. Review whether this is necessary."
            )

        # Cookie checks
        for cookie in response.cookies:
            if urlparse(response.url).scheme == "https":
                if not cookie.secure:
                    add_finding(
                        "Cookie Missing Secure Flag",
                        "Medium",
                        "Cookie may be transmitted without HTTPS.",
                        cookie.name
                    )

            if not cookie.has_nonstandard_attr("HttpOnly"):
                add_finding(
                    "Cookie Missing HttpOnly Flag",
                    "Low",
                    "Cookie may be accessible to client-side scripts.",
                    cookie.name
                )

            if not cookie.has_nonstandard_attr("SameSite"):
                add_finding(
                    "Cookie Missing SameSite Attribute",
                    "Low",
                    "Review cross-site cookie behavior.",
                    cookie.name
                )

        # Form inspection
        parser = FormParser()
        parser.feed(response.text)

        for index, form in enumerate(parser.forms, start=1):
            inputs = form.get("inputs", [])

            token_names = [
                item["name"].lower() for item in inputs
            ]

            has_token = any(
                any(word in name for word in
                    ["csrf", "token", "nonce"])
                for name in token_names
            )

            if form["method"] == "post" and not has_token:
                add_finding(
                    "Possible CSRF Protection Gap",
                    "Medium",
                    "POST form has no recognizable CSRF token field.",
                    "Form number " + str(index)
                )

        # SQL error signatures - passive only
        sql_signatures = [
            "sql syntax",
            "mysql_fetch",
            "ora-00933",
            "sqlite_error",
            "postgresql error",
            "unclosed quotation mark"
        ]

        body = response.text.lower()

        for signature in sql_signatures:
            if signature in body:
                add_finding(
                    "Possible SQL Error Disclosure",
                    "Medium",
                    "Database error signature found in response.",
                    signature
                )

        print("[+] HTTP checks completed")

    except requests.exceptions.SSLError as error:
        add_finding(
            "SSL Verification Failure",
            "High",
            "TLS certificate verification failed.",
            str(error)[:300]
        )

    except requests.RequestException as error:
        print("[-] HTTP error:", error)


# ---------------- SSL/TLS CHECK ----------------

def scan_ssl(host, port):
    print("[+] SSL/TLS assessment")

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (host, port), timeout=TIMEOUT
        ) as connection:

            with context.wrap_socket(
                connection, server_hostname=host
            ) as secure:

                cert = secure.getpeercert()
                expiry = datetime.strptime(
                    cert["notAfter"],
                    "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)

                if expiry < datetime.now(timezone.utc):
                    add_finding(
                        "Expired TLS Certificate",
                        "High",
                        "The TLS certificate has expired."
                    )

                days_left = (
                    expiry - datetime.now(timezone.utc)
                ).days

                if 0 <= days_left <= 30:
                    add_finding(
                        "TLS Certificate Expiring Soon",
                        "Medium",
                        f"Certificate expires in {days_left} days."
                    )

                print("[+] TLS version:", secure.version())
                print("[+] Certificate expiry:", expiry)

    except Exception as error:
        add_finding(
            "TLS Assessment Failed",
            "Info",
            str(error)[:300]
        )


# ---------------- TCP PORT CHECK ----------------

def check_port(host, port):
    try:
        with socket.create_connection(
            (host, port), timeout=1
        ):
            print(f"[OPEN] TCP {port}")
            return port
    except (OSError, TimeoutError):
        return None


def scan_ports(host, ports):
    print("\n[+] Selected TCP port assessment")

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(
            lambda port: check_port(host, port), ports
        )

    for port in results:
        if port:
            add_finding(
                "Open TCP Port",
                "Info",
                f"TCP port {port} is accepting connections.",
                str(port)
            )


# ---------------- TECHNOLOGY DETECTION ----------------

def detect_technology(url):
    print("\n[+] Technology detection")

    try:
        response = requests.get(
            url, timeout=TIMEOUT, verify=True
        )

        technologies = {
            "Server": response.headers.get("Server"),
            "X-Powered-By": response.headers.get("X-Powered-By")
        }

        for name, value in technologies.items():
            if value:
                print(f"[+] {name}: {value}")

        for framework in [
            "wp-content", "drupal", "joomla",
            "react", "next.js", "vue"
        ]:
            if framework.lower() in response.text.lower():
                print("[+] Possible technology:", framework)

    except requests.RequestException:
        print("[-] Technology detection failed")


# ---------------- BASIC API CHECK ----------------

def api_check(url):
    print("\n[+] Basic API assessment")

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    paths = [
        "/openapi.json",
        "/swagger.json"
    ]

    for path in paths:
        try:
            response = requests.get(
                urljoin(base, path),
                timeout=TIMEOUT,
                verify=True
            )

            if response.status_code == 200:
                add_finding(
                    "Public API Documentation",
                    "Info",
                    "API documentation endpoint is publicly accessible.",
                    path
                )

        except requests.RequestException:
            pass


# ---------------- REPORT GENERATION ----------------

def save_json():
    os.makedirs("spy_reports", exist_ok=True)

    report = {
        "tool": APP,
        "version": VERSION,
        "target": TARGET,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "summary": severity_counts(),
        "findings": FINDINGS
    }

    filename = "spy_reports/report.json"

    with open(filename, "w") as file:
        json.dump(report, file, indent=4)

    print("[+] JSON report:", filename)


def save_html():
    import html

    os.makedirs("spy_reports", exist_ok=True)

    content = [
        "<html><head><title>SPY-VULNWEB Report</title>",
        "<style>",
        "body{font-family:Arial;background:#111;color:#eee;padding:25px}",
        "h1{color:#39d98a}table{width:100%;border-collapse:collapse}",
        "td,th{padding:10px;border:1px solid #555;text-align:left}",
        "</style></head><body>",
        "<h1>SPY-VULNWEB Security Report</h1>",
        "<p>Target: " + html.escape(TARGET) + "</p>",
        "<p>Findings: " + str(len(FINDINGS)) + "</p>",
        "<table><tr><th>Name</th><th>Severity</th>",
        "<th>Details</th><th>Evidence</th></tr>"
    ]

    for item in FINDINGS:
        content.append(
            "<tr><td>" + html.escape(item["name"]) +
            "</td><td>" + html.escape(item["severity"]) +
            "</td><td>" + html.escape(item["details"]) +
            "</td><td>" + html.escape(item["evidence"]) +
            "</td></tr>"
        )

    content.append("</table></body></html>")

    filename = "spy_reports/report.html"

    with open(filename, "w") as file:
        file.write("".join(content))

    print("[+] HTML report:", filename)


def save_pdf():
    if not PDF_AVAILABLE:
        print("[-] PDF unavailable. Install reportlab.")
        return

    os.makedirs("spy_reports", exist_ok=True)

    filename = "spy_reports/report.pdf"
    pdf = canvas.Canvas(filename, pagesize=A4)

    width, height = A4
    y = height - 50

    pdf.setTitle("SPY-VULNWEB Report")
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(40, y, "SPY-VULNWEB Security Report")
    y -= 30

    pdf.setFont("Helvetica", 10)
    pdf.drawString(40, y, "Target: " + TARGET[:85])
    y -= 20
    pdf.drawString(40, y, "Total findings: " + str(len(FINDINGS)))
    y -= 30

    for item in FINDINGS:
        if y < 100:
            pdf.showPage()
            y = height - 50

        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(
            40, y,
            (item["severity"] + ": " + item["name"])[:90]
        )
        y -= 17

        pdf.setFont("Helvetica", 9)

        for text in [
            item["details"],
            "Evidence: " + item["evidence"]
        ]:
            pdf.drawString(40, y, text[:100])
            y -= 15

        y -= 10

    pdf.save()
    print("[+] PDF report:", filename)


# ---------------- SCAN ENGINE ----------------

def run_scan(target, do_ports=True):
    global TARGET, FINDINGS

    TARGET = normalize_target(target)
    FINDINGS = []

    parsed = urlparse(TARGET)
    host = parsed.hostname

    print("\n[*] Target:", TARGET)
    print("[*] Starting assessment...\n")

    scan_http(TARGET)

    if parsed.scheme == "https":
        scan_ssl(host, parsed.port or 443)

    detect_technology(TARGET)
    api_check(TARGET)

    if do_ports:
        ports = [
            p for p in COMMON_PORTS
            if p in (parsed.port, 80, 443, 8080, 8443)
        ]

        if not ports:
            ports = [80, 443]

        scan_ports(host, ports)

    print("\n========== SCAN SUMMARY ==========")

    for severity, count in severity_counts().items():
        print(f"{severity}: {count}")

    print("Total findings:", len(FINDINGS))

    save_json()
    save_html()
    save_pdf()


# ---------------- GUI ----------------

def launch_gui():
    import tkinter as tk
    from tkinter import messagebox

    root = tk.Tk()
    root.title("SPY-VULNWEB v1.0")
    root.geometry("760x550")
    root.configure(bg="#101010")

    title = tk.Label(
        root,
        text="SPY-VULNWEB",
        font=("Courier", 25, "bold"),
        fg="#39d98a",
        bg="#101010"
    )
    title.pack(pady=20)

    tk.Label(
        root,
        text="AUTHORIZED WEB SECURITY ASSESSMENT",
        fg="white",
        bg="#101010"
    ).pack()

    entry = tk.Entry(
        root, width=65,
        font=("Arial", 12)
    )
    entry.pack(pady=20)
    entry.insert(0, "https://")

    output = tk.Text(
        root, width=85, height=17,
        bg="#050505", fg="#39d98a",
        font=("Courier", 10)
    )
    output.pack(padx=15, pady=10)

    def start():
        target = entry.get().strip()

        if not target:
            messagebox.showerror(
                "Error", "Enter an authorized target."
            )
            return

        output.delete("1.0", tk.END)
        output.insert(tk.END, "Starting scan...\n")

        def worker():
            try:
                run_scan(target)
                message = (
                    "Scan completed.\n"
                    + json.dumps(severity_counts(), indent=2)
                    + "\nReports saved in spy_reports/"
                )
            except Exception as error:
                message = "Error: " + str(error)

            root.after(
                0,
                lambda: output.insert(tk.END, message + "\n")
            )

        threading.Thread(
            target=worker, daemon=True
        ).start()

    tk.Button(
        root,
        text="START SECURITY SCAN",
        command=start,
        bg="#147d4c",
        fg="white",
        font=("Arial", 12, "bold"),
        padx=20,
        pady=10
    ).pack(pady=10)

    tk.Label(
        root,
        text="Reports: spy_reports/ | Kali Linux only",
        fg="gray",
        bg="#101010"
    ).pack(pady=10)

    root.mainloop()


# ---------------- MAIN ----------------

def main():
    check_kali()

    parser = argparse.ArgumentParser(
        description="SPY-VULNWEB Security Scanner"
    )

    parser.add_argument(
        "-u", "--url",
        help="Authorized target URL"
    )

    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch graphical interface"
    )

    parser.add_argument(
        "--no-ports",
        action="store_true",
        help="Skip TCP port checks"
    )

    args = parser.parse_args()

    banner()

    if args.gui:
        launch_gui()

    elif args.url:
        try:
            run_scan(args.url, not args.no_ports)
        except ValueError as error:
            print("[-]", error)

    else:
        target = input(
            "[?] Enter authorized target URL: "
        )

        try:
            run_scan(target)
        except ValueError as error:
            print("[-]", error)


if __name__ == "__main__":
    main()

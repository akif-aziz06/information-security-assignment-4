"""
Vulnerability Scanner Module
Scans a target web application for common security flaws.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
import time


class Finding:
    """Represents a single vulnerability finding."""
    def __init__(self, name, severity, category, description, evidence, mitigation):
        self.name = name
        self.severity = severity          # Critical, High, Medium, Low, Info
        self.category = category          # e.g. "SQL Injection", "XSS"
        self.description = description
        self.evidence = evidence
        self.mitigation = mitigation

    def to_dict(self):
        return {
            'name': self.name,
            'severity': self.severity,
            'category': self.category,
            'description': self.description,
            'evidence': self.evidence,
            'mitigation': self.mitigation,
        }


class VulnerabilityScanner:
    """Lightweight web vulnerability scanner."""

    def __init__(self, base_url, timeout=10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.findings = []
        self.scan_log = []

    def _log(self, msg):
        self.scan_log.append(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def _get(self, path, **kwargs):
        url = urljoin(self.base_url + '/', path.lstrip('/'))
        return self.session.get(url, timeout=self.timeout, **kwargs)

    def _post(self, path, data, **kwargs):
        url = urljoin(self.base_url + '/', path.lstrip('/'))
        return self.session.post(url, data=data, timeout=self.timeout, **kwargs)

    def _add(self, name, severity, category, desc, evidence, mitigation):
        f = Finding(name, severity, category, desc, evidence, mitigation)
        self.findings.append(f)
        self._log(f"[{severity}] Found: {name}")

    # ── 1. Security Headers Check ───────────────────────────────────────────
    def scan_security_headers(self):
        self._log("Checking security headers...")
        try:
            resp = self._get('/')
        except Exception as e:
            self._log(f"Error connecting: {e}")
            return

        required_headers = {
            'X-Frame-Options': {
                'desc': 'Prevents clickjacking attacks by controlling whether the page can be embedded in iframes.',
                'fix': "Add header: X-Frame-Options: DENY or SAMEORIGIN"
            },
            'Content-Security-Policy': {
                'desc': 'Mitigates XSS and data injection attacks by specifying allowed content sources.',
                'fix': "Add header: Content-Security-Policy: default-src 'self'"
            },
            'X-Content-Type-Options': {
                'desc': 'Prevents MIME-type sniffing which can lead to security vulnerabilities.',
                'fix': "Add header: X-Content-Type-Options: nosniff"
            },
            'X-XSS-Protection': {
                'desc': 'Enables browser built-in XSS filtering.',
                'fix': "Add header: X-XSS-Protection: 1; mode=block"
            },
            'Strict-Transport-Security': {
                'desc': 'Forces HTTPS connections, preventing man-in-the-middle attacks.',
                'fix': "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            },
            'Referrer-Policy': {
                'desc': 'Controls how much referrer information is shared with other sites.',
                'fix': "Add header: Referrer-Policy: strict-origin-when-cross-origin"
            },
        }

        missing = []
        for header, info in required_headers.items():
            if header.lower() not in [h.lower() for h in resp.headers]:
                missing.append(header)
                self._add(
                    f"Missing Security Header: {header}",
                    "Medium",
                    "Missing Security Headers",
                    info['desc'],
                    f"Header '{header}' not found in response.",
                    info['fix']
                )

        if not missing:
            self._log("All security headers present.")

    # ── 2. Information Disclosure ────────────────────────────────────────────
    def scan_info_disclosure(self):
        self._log("Checking for information disclosure...")
        try:
            resp = self._get('/')
        except Exception:
            return

        server = resp.headers.get('Server', '')
        if server:
            self._add(
                "Server Version Disclosed",
                "Low",
                "Information Disclosure",
                "The server reveals its software version in HTTP headers, helping attackers identify known vulnerabilities.",
                f"Server header: {server}",
                "Remove or obscure the Server header. In Flask: use a middleware to strip it."
            )

        powered = resp.headers.get('X-Powered-By', '')
        if powered:
            self._add(
                "Technology Stack Disclosed (X-Powered-By)",
                "Low",
                "Information Disclosure",
                "The X-Powered-By header reveals the backend framework.",
                f"X-Powered-By: {powered}",
                "Remove the X-Powered-By header from responses."
            )

        # Check for HTML comments with sensitive info
        body = resp.text
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        for c in comments:
            if any(kw in c.lower() for kw in ['debug', 'server', 'password', 'key', 'secret', 'token', 'version']):
                self._add(
                    "Sensitive Information in HTML Comments",
                    "Low",
                    "Information Disclosure",
                    "HTML comments contain potentially sensitive information visible to anyone viewing page source.",
                    f"Comment found: <!--{c.strip()}-->",
                    "Remove all sensitive comments from production HTML."
                )

    # ── 3. SQL Injection ─────────────────────────────────────────────────────
    def scan_sql_injection(self):
        self._log("Testing for SQL Injection...")

        # Test login form
        payloads = [
            ("' OR '1'='1' --", "password"),
            ("admin' --", "anything"),
            ("' OR 1=1 --", "test"),
        ]

        for username, password in payloads:
            try:
                resp = self._post('/login', data={'username': username, 'password': password})
                if any(kw in resp.text.lower() for kw in ['welcome', 'login successful', 'dashboard']):
                    self._add(
                        "SQL Injection in Login Form",
                        "Critical",
                        "SQL Injection",
                        "The login form is vulnerable to SQL injection, allowing authentication bypass. "
                        "An attacker can log in as any user without knowing the password.",
                        f"Payload: username='{username}' bypassed authentication.",
                        "Use parameterized queries (prepared statements) instead of string concatenation. "
                        "Example: cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (user, pwd))"
                    )
                    break
            except Exception:
                pass

        # Test search form
        search_payloads = [
            "' UNION SELECT username,password,role FROM users --",
            "' OR '1'='1",
        ]
        for payload in search_payloads:
            try:
                resp = self._post('/search', data={'q': payload})
                if 'admin' in resp.text.lower() and ('password' in resp.text.lower() or 'admin123' in resp.text):
                    self._add(
                        "SQL Injection in Search Form",
                        "Critical",
                        "SQL Injection",
                        "The search form is vulnerable to UNION-based SQL injection, allowing data exfiltration. "
                        "Attackers can extract usernames, passwords, and other sensitive data.",
                        f"Payload: q='{payload}' exposed database contents.",
                        "Use parameterized queries and input validation. Limit database user permissions."
                    )
                    break
                # Check for SQL error messages
                if any(e in resp.text.lower() for e in ['sql error', 'sqlite', 'syntax error', 'operationalerror']):
                    self._add(
                        "SQL Error Messages Exposed",
                        "High",
                        "SQL Injection",
                        "The application exposes raw SQL error messages to users, revealing database structure.",
                        f"SQL error message found in response to payload: {payload}",
                        "Implement generic error handling. Never show raw database errors to users."
                    )
            except Exception:
                pass

    # ── 4. Cross-Site Scripting (XSS) ────────────────────────────────────────
    def scan_xss(self):
        self._log("Testing for Cross-Site Scripting (XSS)...")
        xss_payload = "<script>alert('XSS')</script>"

        # Test reflected XSS on greet page
        try:
            resp = self._get(f'/greet?name={xss_payload}')
            if xss_payload in resp.text:
                self._add(
                    "Reflected XSS in Greet Page",
                    "High",
                    "Cross-Site Scripting (XSS)",
                    "User input is reflected directly in the page without sanitization. "
                    "An attacker can craft a malicious URL that executes JavaScript in the victim's browser.",
                    f"Payload '{xss_payload}' was reflected unescaped in the response.",
                    "Sanitize and escape all user input before rendering. Use template auto-escaping. "
                    "Set Content-Security-Policy header to restrict inline scripts."
                )
        except Exception:
            pass

        # Test stored XSS in comments
        try:
            marker = f"xss_test_{int(time.time())}"
            payload = f"<img src=x onerror=alert('{marker}')>"
            self._post('/comment', data={'name': 'Scanner', 'comment': payload})
            resp = self._get('/comment')
            if payload in resp.text or f"onerror=alert('{marker}')" in resp.text:
                self._add(
                    "Stored XSS in Comments",
                    "High",
                    "Cross-Site Scripting (XSS)",
                    "User input is stored in the database and rendered without sanitization. "
                    "Every visitor to the comments page will execute the malicious script.",
                    f"Stored payload was rendered unescaped: {payload}",
                    "Sanitize input on storage AND escape output on rendering. "
                    "Use libraries like bleach (Python) to clean HTML. Implement CSP headers."
                )
        except Exception:
            pass

    # ── 5. CSRF Check ────────────────────────────────────────────────────────
    def scan_csrf(self):
        self._log("Checking for CSRF protection...")
        pages_with_forms = ['/login', '/comment', '/profile', '/search']

        for path in pages_with_forms:
            try:
                resp = self._get(path)
                soup = BeautifulSoup(resp.text, 'html.parser')
                forms = soup.find_all('form', method=True)
                for form in forms:
                    if form.get('method', '').upper() == 'POST':
                        csrf_inputs = form.find_all('input', attrs={'name': re.compile(r'csrf|token|_token', re.I)})
                        if not csrf_inputs:
                            self._add(
                                f"Missing CSRF Token on {path}",
                                "Medium",
                                "Cross-Site Request Forgery (CSRF)",
                                f"The POST form at {path} has no CSRF token. An attacker can trick "
                                "authenticated users into submitting unwanted actions.",
                                f"No hidden input with csrf/token name found in form at {path}.",
                                "Implement CSRF tokens using Flask-WTF or similar. Add a unique token "
                                "to each form and validate it on the server side."
                            )
            except Exception:
                pass

    # ── 6. Path Traversal ────────────────────────────────────────────────────
    def scan_path_traversal(self):
        self._log("Testing for path traversal...")
        payloads = [
            '../vulnerable_app.py',
            '..\\vulnerable_app.py',
            '../../etc/passwd',
        ]
        for payload in payloads:
            try:
                resp = self._get(f'/file?name={payload}')
                if any(kw in resp.text for kw in ['import ', 'def ', 'flask', 'SELECT', 'root:', '/bin/']):
                    self._add(
                        "Path Traversal / Local File Inclusion",
                        "Critical",
                        "Path Traversal",
                        "The file viewer allows reading files outside the intended directory using ../ sequences. "
                        "An attacker can read source code, configuration files, and system files.",
                        f"Payload '?name={payload}' successfully read a file outside the web root.",
                        "Validate and sanitize file paths. Use os.path.realpath() to resolve paths and "
                        "verify they stay within the allowed directory. Use a whitelist of allowed files."
                    )
                    break
            except Exception:
                pass

    # ── 7. Broken Access Control ─────────────────────────────────────────────
    def scan_broken_access(self):
        self._log("Testing for broken access control...")
        try:
            # Try accessing admin without authentication
            resp = self._get('/admin')
            if resp.status_code == 200 and 'admin' in resp.text.lower():
                if 'username' in resp.text.lower() and 'email' in resp.text.lower():
                    self._add(
                        "Broken Access Control — Admin Panel Exposed",
                        "Critical",
                        "Broken Access Control",
                        "The admin panel is accessible without any authentication or authorization check. "
                        "Any user can view and potentially modify all user data.",
                        "GET /admin returned 200 OK with user data, no login required.",
                        "Implement authentication and role-based authorization. Check user session "
                        "and role before granting access to admin endpoints."
                    )
        except Exception:
            pass

        # Check API endpoint
        try:
            resp = self._get('/api/users')
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    if 'password' in str(data):
                        self._add(
                            "Sensitive Data Exposure via API",
                            "Critical",
                            "Sensitive Data Exposure",
                            "The /api/users endpoint exposes all user records including passwords "
                            "without any authentication.",
                            f"GET /api/users returned {len(data)} user records with passwords.",
                            "Require authentication for API endpoints. Never return password fields. "
                            "Use proper serialization to control which fields are exposed."
                        )
        except Exception:
            pass

    # ── 8. Cookie Security ───────────────────────────────────────────────────
    def scan_cookie_security(self):
        self._log("Checking cookie security...")
        try:
            # Login to get cookies set
            self._post('/login', data={'username': "' OR '1'='1' --", 'password': 'x'})
            for cookie in self.session.cookies:
                issues = []
                if not cookie.has_nonstandard_attr('HttpOnly') and not cookie._rest.get('HttpOnly'):
                    issues.append("Missing HttpOnly flag")
                if not cookie.secure:
                    issues.append("Missing Secure flag")

                if issues:
                    self._add(
                        f"Insecure Cookie: {cookie.name}",
                        "Medium",
                        "Insecure Cookie Configuration",
                        f"Cookie '{cookie.name}' is missing security flags: {', '.join(issues)}. "
                        "This makes it vulnerable to theft via XSS or man-in-the-middle attacks.",
                        f"Cookie '{cookie.name}' flags: {issues}",
                        "Set HttpOnly, Secure, and SameSite=Strict flags on all sensitive cookies. "
                        "Example: response.set_cookie('name', 'value', httponly=True, secure=True, samesite='Strict')"
                    )
        except Exception:
            pass

    # ── Full Scan ────────────────────────────────────────────────────────────
    def full_scan(self, progress_callback=None):
        """Run all scan modules. progress_callback(step, total, message) is optional."""
        self.findings = []
        self.scan_log = []
        self._log(f"Starting full scan of {self.base_url}")

        scans = [
            ("Security Headers", self.scan_security_headers),
            ("Information Disclosure", self.scan_info_disclosure),
            ("SQL Injection", self.scan_sql_injection),
            ("Cross-Site Scripting", self.scan_xss),
            ("CSRF Protection", self.scan_csrf),
            ("Path Traversal", self.scan_path_traversal),
            ("Access Control", self.scan_broken_access),
            ("Cookie Security", self.scan_cookie_security),
        ]

        for i, (name, fn) in enumerate(scans):
            if progress_callback:
                progress_callback(i, len(scans), f"Scanning: {name}...")
            try:
                fn()
            except Exception as e:
                self._log(f"Error in {name} scan: {e}")

        if progress_callback:
            progress_callback(len(scans), len(scans), "Scan complete!")

        self._log(f"Scan complete. Found {len(self.findings)} issues.")
        return self.findings

    def get_summary(self):
        """Return severity counts."""
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

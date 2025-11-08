import re
import asyncio
import aiohttp
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from fpdf import FPDF
from datetime import datetime
import os
from openai import OpenAI
import argparse
import random
from dotenv import load_dotenv  # <-- added for .env support
import sys
import difflib

# Load environment variables from .env file
load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise Exception("Set your OPENAI_API_KEY in the .env file before running")
client = OpenAI(api_key=OPENAI_API_KEY)

# Import paths to scan from separate file
from paths_to_scan import paths_to_scan

# ANSI color codes for console output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

# Global counter for vulnerabilities
vuln_count = 0

# Global log of all scanned URLs
scanned_urls_log = []

# Global scan details
scan_details = {
    "company_name": "",
    "target_url": "",
    "scan_date": "",
    "include_full_log": True
}

# Global semaphore to control request concurrency
request_semaphore = None

# Sensitive directories that should not be publicly accessible
SENSITIVE_DIRECTORIES = [
    "admin", "administrator", "admin1", "admin2", "admin_area", "admin_panel",
    "admin/login", "adminconsole", "admincontrol", "cpanel", "backend", "admincp",
    "admin-console", "cmsadmin", "root", "superuser", "system_admin", "dashboard",
    "backup", "backups", "db_backup", "site-backup", "website_backup",
    "uploads", "upload", "tmp", "temp", "files", "public_files", "private_files",
    "secret", "private", "old_site", "bk", "old", "archive",
    "logs", "log", "debug", "error", "access", "server",
    "config", "configuration", "settings", "env", "environment",
    "database", "db", "mysql", "sql", "dump", "data",
    "git", "svn", "hg", "bzr", "cvs",
    "test", "tests", "testing", "dev", "development", "staging", "sandbox", "demo",
    "example", "examples", "docs", "documentation", "doc",
    "wp-admin", "wp-content", "joomla", "drupal", "magento", "prestashop",
    "img", "images", "img/", "images/","bk", "bk/", "backup", "backup/", "backups", "backups/",
    # Modern frameworks and package dirs
    "storage", "storage/logs", "storage/app", "storage/framework", "bootstrap/cache",
    "var", "var/log",
    "vendor", "node_modules",
    # Admin tools
    "phpmyadmin", "phppgadmin", "_debugbar",
    # Well-known endpoints folder
    ".well-known"
]

def is_sensitive_directory(path: str) -> bool:
    """Check if a path represents a sensitive directory that should not be publicly accessible"""
    # Remove leading/trailing slashes and get the directory name
    clean_path = path.strip('/')
    
    # Check if it's in our sensitive directories list
    if clean_path in SENSITIVE_DIRECTORIES:
        return True
    
    # Also check if it starts with any sensitive directory (for nested paths)
    for sensitive_dir in SENSITIVE_DIRECTORIES:
        if clean_path.startswith(sensitive_dir + '/') or clean_path == sensitive_dir:
            return True
    
    return False

# Suspicious file names/extensions that should not be publicly downloadable
SUSPICIOUS_FILE_EXTENSIONS = {
    "zip", "7z", "rar", "tar", "gz", "bz2",
    "sql", "sqlite", "db", "bak", "backup",
    "env", "pem", "key", "pfx", "cer",
}
SUSPICIOUS_FILE_KEYWORDS = {"backup", "dump", "database", "secrets", "private", "keys"}

def is_suspicious_file(path: str) -> bool:
    name = path.strip("/").split("/")[-1].lower()
    if "." in name:
        ext = name.rsplit(".", 1)[-1]
        if ext in SUSPICIOUS_FILE_EXTENSIONS:
            return True
    base = name.rsplit(".", 1)[0]
    return any(k in base for k in SUSPICIOUS_FILE_KEYWORDS)
# Function to get user input for company name and URL
def get_scan_details():
    print(f"{Colors.BOLD}{Colors.BLUE}🔍 Website Security Scanner{Colors.END}")
    print(f"{Colors.CYAN}{'=' * 50}{Colors.END}")
    
    # Get company name
    while True:
        company_name = input(f"{Colors.YELLOW}Enter company name: {Colors.END}").strip()
        if company_name:
            scan_details["company_name"] = company_name
            break
        else:
            print(f"{Colors.RED}Company name cannot be empty. Please try again.{Colors.END}")
    
    # Get target URL
    while True:
        target_url = input(f"{Colors.YELLOW}Enter target URL (e.g., https://example.com): {Colors.END}").strip()
        if target_url:
            # Ensure URL has protocol
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'https://' + target_url
            scan_details["target_url"] = target_url
            break
        else:
            print(f"{Colors.RED}URL cannot be empty. Please try again.{Colors.END}")
    
    # Set scan date (UK format)
    scan_details["scan_date"] = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    
    print(f"{Colors.GREEN}✅ Scan details captured:{Colors.END}")
    print(f"   Company: {Colors.BOLD}{company_name}{Colors.END}")
    print(f"   URL: {Colors.BOLD}{target_url}{Colors.END}")
    print(f"   Date: {Colors.BOLD}{scan_details['scan_date']}{Colors.END}")

    # Ask whether to include full scan log
    while True:
        resp = input(f"{Colors.YELLOW}Include full scan log in the PDF report? (Y/N): {Colors.END}").strip().lower()
        if resp in ("y", "yes", ""):
            scan_details["include_full_log"] = True
            break
        if resp in ("n", "no"):
            scan_details["include_full_log"] = False
            break
        print(f"{Colors.RED}Please enter Y or N.{Colors.END}")
    print()

# Content sensitivity scoring (simple keyword check)
def score_content_sensitivity(content: str) -> str:
    high_risk_keywords = ["password", "secret", "api_key", "aws_access_key", "private_key", "credentials"]
    medium_risk_keywords = ["token", "auth", "key", "user", "email"]
    content_lower = content.lower()
    if any(k in content_lower for k in high_risk_keywords):
        return "high"
    if any(k in content_lower for k in medium_risk_keywords):
        return "medium"
    return "low"

# AI analysis for uncertain content
def ai_analyze_content(url: str, content: str, context_type="general") -> str:
    prompt = (
        f"You are an AI security auditor. Analyze the following {context_type} content from {url} "
        f"and determine if it poses a security risk. Respond concisely with your confidence and explanation.\n\n"
        f"Content:\n{content[:1500]}"
    )
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=250,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"AI analysis failed: {e}"

# Randomized throttle function
async def throttle(speed: str):
    if speed == "slow":
        delay = random.uniform(2.0, 4.0)
    elif speed == "medium":
        delay = random.uniform(0.3, 0.75)
    else:  # fast
        delay = 0
    if delay > 0:
        await asyncio.sleep(delay)

# Async fetch with timeout (robust for binary content)
async def fetch(session, url):
    try:
        async with session.get(url, timeout=10) as resp:
            raw = await resp.read()  # works for text or binary
            try:
                text = raw.decode("utf-8", errors="ignore")
            except Exception:
                text = ""
            return resp.status, text
    except Exception:
        return None, ""

# Soft-404 detection helpers
SOFT_404_MARKERS = [
    "404", "not found", "page not found", "doesn't exist", "does not exist",
    "can't find", "cannot find", "oops", "we're sorry", "return to home"
]

soft_404_baseline_text = None

def _normalize_html_text(content: str) -> str:
    try:
        soup = BeautifulSoup(content, "html.parser")
        text = soup.get_text(" ")
    except Exception:
        text = content
    # normalize whitespace and lowercase
    return " ".join(text.split()).lower()

def looks_like_soft_404(status: int, content: str) -> bool:
    if status != 200 or not content:
        return False
    text = _normalize_html_text(content)
    # keyword markers
    if any(marker in text for marker in SOFT_404_MARKERS):
        return True
    # similarity to baseline soft-404
    if soft_404_baseline_text:
        try:
            ratio = difflib.SequenceMatcher(None, text[:4000], soft_404_baseline_text[:4000]).ratio()
            if ratio >= 0.92:
                return True
        except Exception:
            pass
    return False

def ensure_trailing_slash(url: str) -> str:
    return url if url.endswith('/') else url + '/'

async def init_soft_404_baseline(session, base_url: str, speed: str):
    global soft_404_baseline_text, request_semaphore
    base = ensure_trailing_slash(base_url)
    random_slug = f"__scanner_missing__{random.randint(100000, 999999)}/"  # no leading slash
    test_url = urljoin(base, random_slug)
    async with request_semaphore:
        await throttle(speed)
        status, content = await fetch(session, test_url)
    if status == 200 and content:
        soft_404_baseline_text = _normalize_html_text(content)

# Analyze a file or directory path
async def analyze_path(session, base_url: str, path: str, findings: list, counters: dict, speed: str):
    global vuln_count, scanned_urls_log, request_semaphore
    base = ensure_trailing_slash(base_url)
    # Always treat paths as relative to base; remove any leading slash
    rel_path = path.lstrip('/')
    full_url = urljoin(base, rel_path)
    
    # Print scanning status
    print(f"{Colors.CYAN}[SCANNING]{Colors.END} {path}")
    
    async with request_semaphore:
        await throttle(speed)
        status, content = await fetch(session, full_url)

    is_dir = path.endswith("/")
    if is_dir:
        counters["directories"] += 1
    else:
        counters["files"] += 1

    # Log the URL scan
    scan_result = {
        "url": full_url,
        "path": path,
        "status": status,
        # Consider 200 as has_content even if response is binary (content may be empty string after decode)
        "has_content": bool(status == 200),
        "vulnerability": None,
        "type": "directory" if is_dir else "file"
    }

    if status == 200:
        # If a suspicious downloadable file is publicly accessible, flag immediately
        if not is_dir and is_suspicious_file(path):
            vuln_count += 1
            scan_result["vulnerability"] = "high"
            print(f"{Colors.GREEN}✅{Colors.END} {Colors.RED}[HIGH]{Colors.END} {Colors.BOLD}{path}{Colors.END} - Publicly downloadable sensitive file")
            findings.append({"level": "high", "url": full_url, "notes": "Publicly downloadable sensitive file", "type": "file"})
        # Soft-404 guard
        # Soft-404 guard: treat as clean if body matches site's not-found template
        if looks_like_soft_404(status, content):
            scan_result["vulnerability"] = "clean"
            print(f"{Colors.GREEN}✅{Colors.END} {Colors.WHITE}[CLEAN]{Colors.END} {path} (soft 404)")
        # Check if this is a sensitive directory that shouldn't be publicly accessible
        elif is_sensitive_directory(path):
            vuln_count += 1
            scan_result["vulnerability"] = "high"
            print(f"{Colors.GREEN}✅{Colors.END} {Colors.RED}[HIGH]{Colors.END} {Colors.BOLD}{path}{Colors.END} - {Colors.YELLOW}Vulns: {vuln_count}{Colors.END}")
            findings.append({"level": "high", "url": full_url, "notes": "Sensitive directory publicly accessible", "type": "directory" if is_dir else "file"})
        elif content.strip():
            # Check content sensitivity for files or directories with content
            score = score_content_sensitivity(content)
            typ = "directory" if is_dir else "file"

            if score == "high":
                vuln_count += 1
                scan_result["vulnerability"] = "high"
                print(f"{Colors.GREEN}✅{Colors.END} {Colors.RED}[HIGH]{Colors.END} {Colors.BOLD}{path}{Colors.END} - {Colors.YELLOW}Vulns: {vuln_count}{Colors.END}")
                findings.append({"level": "high", "url": full_url, "notes": "Auto-detected sensitive content", "type": typ})
            elif score == "medium":
                result = ai_analyze_content(full_url, content)
                vuln_count += 1
                scan_result["vulnerability"] = "medium"
                print(f"{Colors.GREEN}✅{Colors.END} {Colors.YELLOW}[MEDIUM]{Colors.END} {Colors.BOLD}{path}{Colors.END} - {Colors.YELLOW}Vulns: {vuln_count}{Colors.END}")
                findings.append({"level": "medium", "url": full_url, "notes": result, "type": typ})
            else:
                scan_result["vulnerability"] = "clean"
                print(f"{Colors.GREEN}✅{Colors.END} {Colors.WHITE}[CLEAN]{Colors.END} {path}")
        else:
            scan_result["vulnerability"] = "clean"
            print(f"{Colors.GREEN}✅{Colors.END} {Colors.WHITE}[CLEAN]{Colors.END} {path}")
    else:
        # Treat 401/403 on sensitive paths as medium (exists but restricted)
        if status in (401, 403) and is_sensitive_directory(path):
            vuln_count += 1
            scan_result["vulnerability"] = "medium"
            print(f"{Colors.GREEN}✅{Colors.END} {Colors.YELLOW}[MEDIUM]{Colors.END} {Colors.BOLD}{path}{Colors.END} - {Colors.YELLOW}Vulns: {vuln_count}{Colors.END}")
            findings.append({"level": "medium", "url": full_url, "notes": f"Restricted access ({status}) on sensitive path", "type": "directory" if is_dir else "file"})
        else:
            scan_result["vulnerability"] = "clean"
            print(f"{Colors.GREEN}✅{Colors.END} {Colors.WHITE}[CLEAN]{Colors.END} {path}")
    
    scanned_urls_log.append(scan_result)

# Common CDN libraries to skip (unlikely to contain sensitive data)
CDN_LIBRARIES = [
    "bootstrap", "jquery", "react", "vue", "angular", "lodash", "moment", "axios",
    "fontawesome", "googleapis", "gstatic", "cloudflare", "jsdelivr", "unpkg",
    "cdnjs", "bootcdn", "staticfile", "cdn.bootcss", "cdn.jsdelivr.net",
    "code.jquery.com", "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com"
]

def should_skip_js_file(js_path: str) -> bool:
    """Check if JS file should be skipped (CDN library)"""
    js_path_lower = js_path.lower()
    return any(lib in js_path_lower for lib in CDN_LIBRARIES)

# Analyze JS files found in main page
async def analyze_js(session, base_url: str, findings: list, counters: dict, speed: str):
    global vuln_count, scanned_urls_log, request_semaphore
    print(f"{Colors.CYAN}[SCANNING]{Colors.END} Main page for JS files")
    
    base = ensure_trailing_slash(base_url)
    async with request_semaphore:
        await throttle(speed)
        status, content = await fetch(session, base)
    counters["files"] += 1  # counting homepage as scanned file

    if status != 200:
        print(f"{Colors.RED}[ERROR]{Colors.END} Could not access main page")
        return

    soup = BeautifulSoup(content, "html.parser")
    scripts = soup.find_all("script", src=True)
    
    if not scripts:
        print(f"{Colors.GREEN}✅{Colors.END} {Colors.WHITE}[CLEAN]{Colors.END} No external JS files found")
        return

    for script in scripts:
        js_url = urljoin(base_url, script["src"])
        js_path = script["src"]
        
        # Skip CDN libraries
        if should_skip_js_file(js_path):
            print(f"{Colors.PURPLE}⏭️{Colors.END} {Colors.WHITE}[SKIPPED]{Colors.END} CDN library: {js_path}")
            # Log skipped files too
            scan_result = {
                "url": js_url,
                "path": js_path,
                "status": "skipped",
                "has_content": False,
                "vulnerability": "skipped",
                "type": "file"
            }
            scanned_urls_log.append(scan_result)
            continue
            
        print(f"{Colors.CYAN}[SCANNING]{Colors.END} JS: {js_path}")
        
        async with request_semaphore:
            await throttle(speed)
            status, js_content = await fetch(session, js_url)
        counters["files"] += 1

        # Log the JS file scan
        scan_result = {
            "url": js_url,
            "path": js_path,
            "status": status,
            "has_content": bool(status == 200 and js_content.strip()),
            "vulnerability": None,
            "type": "file"
        }

        if status == 200 and js_content.strip():
            score = score_content_sensitivity(js_content)
            if score == "high":
                vuln_count += 1
                scan_result["vulnerability"] = "high"
                print(f"{Colors.GREEN}✅{Colors.END} {Colors.RED}[HIGH]{Colors.END} {Colors.BOLD}JS: {js_path}{Colors.END} - {Colors.YELLOW}Vulns: {vuln_count}{Colors.END}")
                findings.append({"level": "high", "url": js_url, "notes": "Sensitive key/secret in JS", "type": "file"})
            elif score == "medium":
                result = ai_analyze_content(js_url, js_content, context_type="js")
                vuln_count += 1
                scan_result["vulnerability"] = "medium"
                print(f"{Colors.GREEN}✅{Colors.END} {Colors.YELLOW}[MEDIUM]{Colors.END} {Colors.BOLD}JS: {js_path}{Colors.END} - {Colors.YELLOW}Vulns: {vuln_count}{Colors.END}")
                findings.append({"level": "medium", "url": js_url, "notes": result, "type": "file"})
            else:
                scan_result["vulnerability"] = "clean"
                print(f"{Colors.GREEN}✅{Colors.END} {Colors.WHITE}[CLEAN]{Colors.END} JS: {js_path}")
        else:
            scan_result["vulnerability"] = "clean"
            print(f"{Colors.GREEN}✅{Colors.END} {Colors.WHITE}[CLEAN]{Colors.END} JS: {js_path} (no content)")
        
        scanned_urls_log.append(scan_result)

# PDF report generator (styled with logo, modern fonts, and improved tables)
class PDFReport(FPDF):
    def header(self):
        try:
            logo_path = os.path.join(os.path.dirname(__file__), "images", "logo.png")
            if os.path.isfile(logo_path):
                # Place logo at top-left (width ~28mm), keep aspect ratio
                self.image(logo_path, x=15, y=10, w=28)
        except Exception:
            # If logo fails, continue without it
            pass

        self.set_xy(15, 12)
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(20, 40, 80)
        self.cell(0, 10, "Website Security Scan Report", 0, 1, "R")

        self.set_font("Helvetica", "B", 12)
        self.set_text_color(0, 0, 0)
        self.cell(0, 8, f"Company: {scan_details['company_name']}", 0, 1, "R")
        self.set_font("Helvetica", "", 10)
        self.cell(0, 6, f"Target URL: {scan_details['target_url']}", 0, 1, "R")
        self.cell(0, 6, f"Scan Date: {scan_details['scan_date']}", 0, 1, "R")

        # Separator line
        self.ln(2)
        self.set_draw_color(220, 223, 230)
        self.set_line_width(0.4)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f"Page {self.page_no()}", 0, 0, "C")

def save_report_to_pdf(findings: list, counters: dict) -> str:
    pdf = PDFReport()
    # Margins and auto page break
    pdf.set_margins(15, 18, 15)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # Summary card
    pdf.set_fill_color(245, 247, 250)  # light gray-blue
    pdf.set_draw_color(222, 226, 233)
    pdf.set_text_color(20, 20, 20)
    pdf.set_line_width(0.3)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "Scan Summary", 0, 1)
    pdf.set_font("Helvetica", "", 11)

    pdf.set_x(15)
    pdf.multi_cell(0, 8, f"Files scanned: {counters.get('files',0)}", 0, 1, fill=False)
    pdf.set_x(15)
    pdf.multi_cell(0, 8, f"Directories scanned: {counters.get('directories',0)}", 0, 1, fill=False)
    pdf.set_x(15)
    pdf.multi_cell(0, 8, f"Potential issues found: {len(findings)}", 0, 1, fill=False)
    pdf.ln(5)

    # Findings details as styled table
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "Details", 0, 1)
    if not findings:
        pdf.set_font("Helvetica", "I", 11)
        pdf.cell(0, 8, "No security issues detected.", 1, 1, "C")
    else:
        header_fill = (240, 244, 248)
        row_alt_fill = (249, 251, 253)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(*header_fill)
        pdf.set_draw_color(220, 223, 230)
        pdf.set_text_color(20, 40, 80)
        # Columns: Level (22) | Type (22) | URL (80) | Notes (56) = 180
        pdf.cell(22, 8, "Level", 1, 0, "C", True)
        pdf.cell(22, 8, "Type", 1, 0, "C", True)
        pdf.cell(80, 8, "URL", 1, 0, "L", True)
        pdf.cell(56, 8, "Notes", 1, 1, "L", True)

        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(15, 15, 15)
        fill_toggle = False
        for f in findings:
            if fill_toggle:
                pdf.set_fill_color(*row_alt_fill)
            else:
                pdf.set_fill_color(255, 255, 255)
            fill_toggle = not fill_toggle

            level = (f.get("level") or "").upper()
            typ = (f.get("type") or "").capitalize()
            url = f.get("url") or ""
            notes = f.get("notes") or ""
            # Truncate to keep row heights clean
            url_disp = (url[:76] + "...") if len(url) > 79 else url
            notes_disp = (notes[:53] + "...") if len(notes) > 56 else notes

            # Color-code level text
            if level == "HIGH":
                level_color = (200, 30, 30)
            elif level == "MEDIUM":
                level_color = (200, 120, 20)
            else:
                level_color = (30, 140, 50)

            # Level
            pdf.set_text_color(*level_color)
            pdf.cell(22, 7, level, 1, 0, "C", True)
            # Type
            pdf.set_text_color(15, 15, 15)
            pdf.cell(22, 7, typ, 1, 0, "C", True)
            # URL
            pdf.cell(80, 7, url_disp, 1, 0, "L", True)
            # Notes
            pdf.cell(56, 7, notes_disp, 1, 1, "L", True)

    # Complete scan log (styled table) - optional
    if scan_details.get("include_full_log", True):
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Complete Scan Log", 0, 1, "C")
        pdf.ln(2)

        # Table header
        header_fill = (240, 244, 248)
        row_alt_fill = (249, 251, 253)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(*header_fill)
        pdf.set_draw_color(220, 223, 230)
        pdf.set_text_color(20, 40, 80)
        pdf.cell(100, 8, "Path", 1, 0, "L", True)
        pdf.cell(25, 8, "Status", 1, 0, "C", True)
        pdf.cell(25, 8, "Result", 1, 0, "C", True)
        pdf.cell(25, 8, "Type", 1, 1, "C", True)

        # Table rows
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(15, 15, 15)
        fill_toggle = False
        # Also deduplicate any duplicates that slipped through by path key
        seen_paths = set()
        for scan in scanned_urls_log:
            path_key = (scan.get("path") or "").strip("/")
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)

            if fill_toggle:
                pdf.set_fill_color(*row_alt_fill)
            else:
                pdf.set_fill_color(255, 255, 255)
            fill_toggle = not fill_toggle

            display_path = scan["path"][:95] + "..." if len(scan["path"]) > 98 else scan["path"]

            if scan["vulnerability"] == "high":
                pdf.set_text_color(200, 30, 30)  # red-ish
                result_symbol = "HIGH"
            elif scan["vulnerability"] == "medium":
                pdf.set_text_color(200, 120, 20)  # orange-ish
                result_symbol = "MED"
            elif scan["vulnerability"] == "skipped":
                pdf.set_text_color(120, 120, 120)  # gray
                result_symbol = "SKIP"
            else:
                pdf.set_text_color(30, 140, 50)  # green-ish
                result_symbol = "CLEAN"

            pdf.cell(100, 7, display_path, 1, 0, "L", True)
            pdf.cell(25, 7, str(scan["status"]), 1, 0, "C", True)
            pdf.cell(25, 7, result_symbol, 1, 0, "C", True)
            pdf.cell(25, 7, scan["type"], 1, 1, "C", True)

            # Reset text color for next row
            pdf.set_text_color(15, 15, 15)

    # Summary statistics as table
    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(20, 40, 80)
    pdf.cell(0, 8, "Scan Statistics", 0, 1)

    header_fill = (240, 244, 248)
    row_alt_fill = (249, 251, 253)

    # Table header
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(*header_fill)
    pdf.set_draw_color(220, 223, 230)
    pdf.set_text_color(20, 40, 80)
    pdf.cell(120, 8, "Metric", 1, 0, "L", True)
    pdf.cell(60, 8, "Value", 1, 1, "C", True)

    # Table rows
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(20, 20, 20)
    total_scanned = len(scanned_urls_log)
    high_vulns = sum(1 for scan in scanned_urls_log if scan["vulnerability"] == "high")
    medium_vulns = sum(1 for scan in scanned_urls_log if scan["vulnerability"] == "medium")
    clean_scans = sum(1 for scan in scanned_urls_log if scan["vulnerability"] == "clean")
    skipped_scans = sum(1 for scan in scanned_urls_log if scan["vulnerability"] == "skipped")

    stats_rows = [
        ("Total URLs scanned", str(total_scanned)),
        ("High risk vulnerabilities", str(high_vulns)),
        ("Medium risk vulnerabilities", str(medium_vulns)),
        ("Clean scans", str(clean_scans)),
        ("Skipped (CDN libraries)", str(skipped_scans)),
    ]
    fill_toggle = False
    for metric, value in stats_rows:
        if fill_toggle:
            pdf.set_fill_color(*row_alt_fill)
        else:
            pdf.set_fill_color(255, 255, 255)
        fill_toggle = not fill_toggle
        pdf.cell(120, 7, metric, 1, 0, "L", True)
        pdf.cell(60, 7, value, 1, 1, "C", True)

    # Generate filename with company name
    company_safe = "".join(c for c in scan_details['company_name'] if c.isalnum() or c in (' ', '-', '_')).rstrip()
    filename = f"security_scan_{company_safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(filename)
    return filename

async def run_full_scan(base_url: str, speed: str):
    global vuln_count, scanned_urls_log, request_semaphore
    vuln_count = 0  # Reset counter for new scan
    scanned_urls_log = []  # Reset log for new scan
    findings = []
    counters = {"files": 0, "directories": 0}

    # Deduplicate paths to avoid scanning /backup and /backup/ separately
    def normalize_path_key(p: str) -> str:
        return p.strip("/")

    unique_paths = []
    seen_keys = set()
    for p in paths_to_scan:
        key = normalize_path_key(p)
        if key not in seen_keys:
            seen_keys.add(key)
            unique_paths.append(p)

    print(f"{Colors.BOLD}{Colors.BLUE}🔍 Starting security scan of {base_url}{Colors.END}")
    print(f"{Colors.CYAN}📊 Total paths to scan: {len(unique_paths)} (deduplicated){Colors.END}")
    print(f"{Colors.CYAN}⚡ Scan speed: {speed}{Colors.END}")
    print("-" * 60)

    # Set concurrency based on speed
    if speed == "slow":
        concurrency_limit = 1
    elif speed == "medium":
        concurrency_limit = 5
    else:
        concurrency_limit = 20

    request_semaphore = asyncio.Semaphore(concurrency_limit)

    connector = aiohttp.TCPConnector(limit=concurrency_limit, limit_per_host=concurrency_limit)

    normalized_base = ensure_trailing_slash(base_url)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Initialize soft-404 baseline for this target
        await init_soft_404_baseline(session, normalized_base, speed)
        tasks = [analyze_path(session, normalized_base, path, findings, counters, speed) for path in unique_paths]
        await asyncio.gather(*tasks)
        await analyze_js(session, normalized_base, findings, counters, speed)

    print("-" * 60)
    print(f"{Colors.BOLD}{Colors.GREEN}✅ Scan completed!{Colors.END}")
    print(f"{Colors.YELLOW}📈 Total vulnerabilities found: {vuln_count}{Colors.END}")
    print(f"{Colors.CYAN}📁 Files scanned: {counters.get('files', 0)}{Colors.END}")
    print(f"{Colors.CYAN}📂 Directories scanned: {counters.get('directories', 0)}{Colors.END}")

    report_path = save_report_to_pdf(findings, counters)
    return report_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Website audit scanner with throttling and AI assistance")
    parser.add_argument("--speed", choices=["fast", "medium", "slow"], default="slow",
                        help="Scan speed with throttling delay (default: slow)")

    args = parser.parse_args()
    
    # Get scan details from user
    get_scan_details()

    report = asyncio.run(run_full_scan(scan_details["target_url"], args.speed))
    print(f"{Colors.BOLD}{Colors.GREEN}📄 Report saved to: {report}{Colors.END}")

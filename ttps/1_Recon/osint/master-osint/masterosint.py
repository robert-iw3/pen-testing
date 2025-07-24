#!/usr/bin/env python3

import time
import sys
import os
import re
import json
import webbrowser
from datetime import datetime

try:
    import requests
except ImportError:
    print("Error: 'requests' library not found. Please install it with 'pip install requests'.")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: 'beautifulsoup4' library not found. Please install it with 'pip install beautifulsoup4'.")
    sys.exit(1)

try:
    from waybackpy import WaybackMachineCDXServerAPI
except ImportError:
    print("Error: 'waybackpy' library not found. Please install it with 'pip install waybackpy'.")
    sys.exit(1)

try:
    import spacy
    SPACY_NLP = spacy.load("en_core_web_sm")
    SPACY_ENABLED = True
except Exception:
    SPACY_ENABLED = False
    print("Warning: 'spacy' or 'en_core_web_sm' model not found. Website Metadata & Entity Scraper limited.")
    print("Run: pip install spacy && python -m spacy download en_core_web_sm")

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, number_type, PhoneNumberType
    PHONENUMBERS_ENABLED = True
except ImportError:
    PHONENUMBERS_ENABLED = False
    print("Warning: 'phonenumbers' module not found. Phone Number Investigation disabled.")
    print("Run: pip install phonenumbers")

# Colors
BLUE = "\033[34m"
WHITE = "\033[37m"
RESET = "\033[0m"
BOLD_BLUE = "\033[1;34m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"

def print_logo():
    logo = BOLD_BLUE + r"""
  __  __           _____ _______ ______ _____      ____   _____ _____ _   _ _______
 |  \/  |   /\    / ____|__   __|  ____|  __ \    / __ \ / ____|_   _| \ | |__ __|
 | \  / |  /  \  | (___    | |  | |__  | |__) |  | |  | | (___   | | |  \| | | |
 | |\/| | / /\ \  \___ \   | |  |  __| |  _  /   | |  | |\___ \  | | | . ` | | |
 | |  | |/ ____ \ ____) |  | |  | |____| | \ \   | |__| |____) |_| |_| |\  | | |
 |_|  |_/_/    \_\_____/   |_|  |______|_|  \_\   \____/|_____/|_____|_| \_| |_|
""" + RESET
    print(logo)
    print()
    print(f"{BLUE}Welcome to MASTER OSINT FOR BEGINNERS - Enhanced Edition!{RESET}\n")
    print(f"{BOLD_BLUE}Creator: Tech Enthusiast {RESET}\n")
    print(f"{YELLOW}This tool provides a foundational suite of OSINT modules. Remember, ethical and legal use is paramount.{RESET}\n")

def print_blue_heading(text, description=""):
    print(f"\n{BOLD_BLUE}[ {text} ]{RESET}")
    if description:
        print(f"{description}\n")

def print_menu():
    options = [
        "Image Geolocation (EXIF & Manual Guidance)",
        "Social Media Investigation (Username Recon & Tools)",
        "Email Analysis (Breaches & Open Source)",
        "Email Lookup & Verification (External Services)",
        "Domain Investigation (WHOIS, DNS, Subdomains)",
        "Metadata Extraction (File Analysis Guidance)",
        "Google Dorking (Advanced Search)",
        "Wayback Machine Lookup (Historical Web Content)",
        "IP Geolocation & Blacklist Check (Network Recon)",
        "Website Metadata & Entity Scraper (Deep Web Content Analysis)",
        "Phone Number Investigation (Validation & Dorking)",
        "Reverse Image Search (Visual Reconnaissance)",
        "Geospatial Intelligence (GEOINT)",
        "Exit"
    ]
    print("\nChoose an OSINT module:\n")
    for i, opt in enumerate(options, 1):
        print(f"{WHITE}[{BLUE}{i}{WHITE}]{RESET} {opt}")
    print()

def print_menu_options():
    return [
        "Image Geolocation (EXIF & Manual Guidance)",
        "Social Media Investigation (Username Recon & Tools)",
        "Email Analysis (Breaches & Open Source)",
        "Email Lookup & Verification (External Services)",
        "Domain Investigation (WHOIS, DNS, Subdomains)",
        "Metadata Extraction (File Analysis Guidance)",
        "Google Dorking (Advanced Search)",
        "Wayback Machine Lookup (Historical Web Content)",
        "IP Geolocation & Blacklist Check (Network Recon)",
        "Website Metadata & Entity Scraper (Deep Web Content Analysis)",
        "Phone Number Investigation (Validation & Dorking)",
        "Reverse Image Search (Visual Reconnaissance)",
        "Geospatial Intelligence (GEOINT)",
        "Exit"
    ]

def input_menu_choice():
    return input(f"Select option {WHITE}[{BLUE}1-{len(print_menu_options())}{WHITE}]{RESET}: ").strip()

# Module 1: Image Geolocation
def image_geolocation():
    try:
        import exifread
    except ImportError:
        print(f"{RED}Error: 'exifread' module not found. Please install it with 'pip install exifread'.{RESET}")
        return
    print_blue_heading(
        "IMAGE GEOLOCATION (EXIF & Manual Guidance)",
        "Extract GPS coordinates from an image's EXIF metadata. If no EXIF data, guidance provided."
    )
    img_path = input("Enter path to image file: ").strip()
    if not os.path.exists(img_path):
        print(f"{RED}Error: File not found at '{img_path}'.{RESET}")
        return
    try:
        with open(img_path, 'rb') as f:
            tags = exifread.process_file(f)
            if not tags:
                print(f"{YELLOW}No EXIF tags found. Try Reverse Image Search module.{RESET}")
                return
            gps_latitude_ref = tags.get('GPS GPSLatitudeRef')
            gps_latitude = tags.get('GPS GPSLatitude')
            gps_longitude_ref = tags.get('GPS GPSLongitudeRef')
            gps_longitude = tags.get('GPS GPSLongitude')

            if gps_latitude and gps_latitude_ref and gps_longitude and gps_longitude_ref:
                def convert_to_degrees(value):
                    d = float(value.values[0].num) / float(value.values[0].den)
                    m = float(value.values[1].num) / float(value.values[1].den)
                    s = float(value.values[2].num) / float(value.values[2].den)
                    return d + (m / 60.0) + (s / 3600.0)
                lat_deg = convert_to_degrees(gps_latitude)
                if gps_latitude_ref.values[0] == 'S':
                    lat_deg *= -1
                lon_deg = convert_to_degrees(gps_longitude)
                if gps_longitude_ref.values[0] == 'W':
                    lon_deg *= -1
                print(f"{GREEN}GPS Data Found:{RESET}")
                print(f"  Latitude: {lat_deg}")
                print(f"  Longitude: {lon_deg}")
                print(f"\n{WHITE}Tip:{RESET} Use Google Maps: {BLUE}https://www.google.com/maps/search/?api=1&query={lat_deg},{lon_deg}{RESET}")
            else:
                print(f"{YELLOW}No GPS EXIF data found.{RESET} Try manual image content analysis.")
    except Exception as e:
        print(f"{RED}Image processing error: {e}{RESET}")

# Module 2: Social Media Investigation
def social_media_investigation():
    print_blue_heading(
        "SOCIAL MEDIA INVESTIGATION",
        "Generate social profile URLs for a username and consider advanced lookups."
    )
    username = input("Enter username to search: ").strip()
    if not username:
        print(f"{RED}No username entered. Returning to menu.{RESET}")
        return
    platforms = {
        "Facebook": f"https://facebook.com/{username}",
        "Twitter (X)": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Telegram": f"https://t.me/{username}",
        "LinkedIn": f"https://linkedin.com/in/{username}",
        "GitHub": f"https://github.com/{username}",
        "Reddit": f"https://reddit.com/user/{username}",
        "YouTube": f"https://www.youtube.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Medium": f"https://medium.com/@{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "Snapchat": f"https://www.snapchat.com/add/{username}",
        "Vimeo": f"https://vimeo.com/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Tumblr": f"https://{username}.tumblr.com",
        "Quora": f"https://www.quora.com/profile/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "Twitch": f"https://twitch.tv/{username}",
        "Patreon": f"https://www.patreon.com/{username}",
        "Blogger": f"https://{username}.blogspot.com",
        "Goodreads": f"https://www.goodreads.com/{username}",
        "VK": f"https://vk.com/{username}",
        "Ok.ru": f"https://ok.ru/{username}",
        "Dribbble": f"https://dribbble.com/{username}",
        "Flickr": f"https://www.flickr.com/people/{username}",
        "HackerNews": f"https://news.ycombinator.com/user?id={username}",
        "Badoo": f"https://badoo.com/profile/{username}",
        "Ello": f"https://ello.co/{username}",
        "DeviantArt": f"https://www.deviantart.com/{username}",
        "Mixcloud": f"https://www.mixcloud.com/{username}/",
        "Periscope": f"https://www.pscp.tv/{username}",
    }
    print(f"\n{BLUE}Profile URLs for '{username}':{RESET}")
    for name, url in platforms.items():
        print(f"{BLUE}{name.ljust(15)}:{RESET} {url}")
    print(f"\n{YELLOW}Use tools like WhatsMyName.app for extensive recon.{RESET}")

# Module 3: Email Analysis
def email_analysis():
    print_blue_heading(
        "EMAIL ANALYSIS (Breaches & Open Source)",
        "Check email breaches and search public pastes and Google."
    )
    email = input("Enter email address: ").strip()
    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
        print(f"{RED}Invalid email format.{RESET}")
        return
    hibp_api_key = "YOUR_HIBP_API_KEY"
    if hibp_api_key == "YOUR_HIBP_API_KEY":
        print(f"{YELLOW}Warning: HIBP API key not set. Skipping breach check.{RESET}")
        print("Manual: https://haveibeenpwned.com/Account/PwnedWebsites")
    else:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {"hibp-api-key": hibp_api_key, "user-agent": "MASTER-OSINT-TOOL"}
        try:
            r = requests.get(url, headers=headers)
            if r.status_code == 200:
                breaches = r.json()
                print(f"{GREEN}Breached in {len(breaches)} breach(es):{RESET}")
                for b in breaches:
                    print(f" - {BLUE}{b['Name']}{RESET} ({b['BreachDate']})")
            elif r.status_code == 404:
                print(f"{GREEN}No breaches found.{RESET}")
            else:
                print(f"{RED}HIBP HTTP Error {r.status_code}{RESET}")
        except Exception as e:
            print(f"{RED}Error querying HIBP: {e}{RESET}")

    print(f"\n{BLUE}--- Searching Pastebin ---{RESET}")
    pastebin_search_url = "https://scrape.pastebin.com/api_scraping.php?limit=50"
    try:
        r = requests.get(pastebin_search_url, timeout=10)
        if r.status_code == 200:
            pastes = r.json()
            matches = []
            print("Scanning recent pastes...")
            for paste in pastes:
                paste_key = paste.get('key')
                if paste_key:
                    paste_url = f"https://pastebin.com/raw/{paste_key}"
                    try:
                        content = requests.get(paste_url, timeout=5).text
                        if email.lower() in content.lower():
                            matches.append(paste_url)
                    except:
                        pass
                    time.sleep(0.5)
            if matches:
                print(f"{GREEN}Found {len(matches)} pastes containing the email:{RESET}")
                for m in matches:
                    print(f" - {m}")
            else:
                print(f"{YELLOW}No pastes found containing the email.{RESET}")
    except:
        pass

    print(f"\n{BLUE}--- Opening Google Search ---{RESET}")
    webbrowser.open(f"https://www.google.com/search?q=\"{email}\"")

# Module 4: Email Lookup and Verification
def email_lookup_and_verification():
    print_blue_heading(
        "EMAIL LOOKUP & VERIFICATION",
        "Uses Hunter.io, ReverseContact.com, and Epieos for lookup."
    )
    email = input("Enter email address for lookup: ").strip()
    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
        print(f"{RED}Invalid email format.{RESET}")
        return
    hunter_api_key = "YOUR_HUNTER_IO_API_KEY"
    if hunter_api_key == "YOUR_HUNTER_IO_API_KEY":
        print(f"{YELLOW}Hunter.io API key missing. Skipping Hunter.io verification.{RESET}")
        print(f"Manual: https://hunter.io/verify")
    else:
        print(f"\n{BLUE}Hunter.io Results:{RESET}")
        try:
            r = requests.get(f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={hunter_api_key}", timeout=10)
            if r.status_code == 200:
                data = r.json().get('data', {})
                print(f"Status: {data.get('status')}")
                print(f"Result: {data.get('result')}")
                print(f"Score: {data.get('score')}")
                print(f"Disposable: {RED+'Yes'+RESET if data.get('disposable') else 'No'}")
                print(f"MX Records: {RED+'None'+RESET if not data.get('mx_records') else 'Present'}")
                print(f"SMTP Check: {data.get('smtp_check')}")
                sources = data.get('sources', [])
                if sources:
                    print("Sources (Up to 3):")
                    for s in sources[:3]:
                        print(f" - {s.get('domain')} ({s.get('uri')})")
            else:
                print(f"{RED}Hunter.io HTTP {r.status_code}{RESET}")
        except Exception as e:
            print(f"{RED}Error querying Hunter.io: {e}{RESET}")
    print("\nReverseContact.com Lookup (Manual):")
    print(f"URL: {BLUE}https://www.reversecontact.com/{RESET}\n")

    print("Epieos Lookup (Manual):")
    print(f"URL: {BLUE}https://epieos.com/{RESET}\n")

# Module 5: Domain Investigation
def find_subdomains_crtsh(domain, max_retries=3, delay=8):
    print(f"\n{BLUE}Searching Subdomains via crt.sh...{RESET}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {'User-Agent': 'MASTER-OSINT-TOOL/1.0'}
    subdomains = set()

    for attempt in range(max_retries):
        try:
            r = requests.get(url, headers=headers, timeout=40)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name_val = entry.get('name_value', '')
                    for sub in name_val.split('\n'):
                        sub = sub.strip().strip('.')
                        if sub.endswith('.' + domain) or sub == domain:
                            subdomains.add(sub)
                break
            else:
                print(f"{YELLOW}crt.sh HTTP {r.status_code} on attempt {attempt+1}/{max_retries}{RESET}")
        except Exception as e:
            print(f"{YELLOW}crt.sh attempt {attempt+1} error: {e}{RESET}")
        if attempt < max_retries -1:
            print(f"Retrying in {delay} seconds...")
            time.sleep(delay)

    if subdomains:
        print(f"{GREEN}Found {len(subdomains)} subdomains:{RESET}")
        for s in sorted(subdomains):
            print(f" - {s}")
    else:
        print(f"{YELLOW}No subdomains found or failed after retries.{RESET}")
    return sorted(subdomains)

def domain_investigation():
    try:
        import tldextract; import whois; import dns.resolver
    except ImportError as e:
        print(f"{RED}Required modules missing: {e}. Please install them.{RESET}")
        return

    print_blue_heading(
        "DOMAIN INVESTIGATION",
        "WHOIS, DNS records, and subdomain enumeration."
    )
    domain_input = input(f"{BLUE}Enter domain or URL: {RESET}").strip()
    if not domain_input:
        print(f"{RED}No input.{RESET}")
        return

    if domain_input.startswith(('http://', 'https://')):
        domain_input = domain_input.split("://")[1].split('/')[0]

    ext = tldextract.extract(domain_input)
    if not ext.domain or not ext.suffix:
        print(f"{RED}Invalid domain.{RESET}")
        return

    domain = f"{ext.domain}.{ext.suffix}"
    print(f"{BLUE}Analyzing domain:{RESET} {WHITE}{domain}{RESET}")

    print(f"\n{BLUE}WHOIS Lookup:{RESET}\n")
    try:
        w = whois.whois(domain)
        registrar = ", ".join(w.registrar) if isinstance(w.registrar, list) else (w.registrar or "N/A")
        print(f"{BLUE}Registrar:{RESET} {WHITE}{registrar}{RESET}\n")

        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        creation_str = creation_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_date, datetime) else "N/A"
        print(f"{BLUE}Creation Date:{RESET} {WHITE}{creation_str}{RESET}\n")

        if isinstance(creation_date, datetime):
            age_days = (datetime.now() - creation_date).days
            print(f"{BLUE}Domain Age:{RESET} {WHITE}{age_days} days{RESET}\n")

        expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        expiration_str = expiration_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(expiration_date, datetime) else "N/A"
        print(f"{BLUE}Expiration Date:{RESET} {WHITE}{expiration_str}{RESET}\n")

        ns = ", ".join(w.name_servers) if w.name_servers else "N/A"
        print(f"{BLUE}Name Servers:{RESET} {WHITE}{ns}{RESET}\n")

        stat = w.status
        if stat:
            status_str = ", ".join(stat) if isinstance(stat, list) else stat
            print(f"{BLUE}Status:{RESET} {WHITE}{status_str}{RESET}\n")
    except Exception as e:
        print(f"{RED}WHOIS lookup failed: {e}{RESET}")

    print(f"\n{BLUE}DNS Records:{RESET}\n")
    try:
        for record in ['A','MX','NS']:
            answers = dns.resolver.resolve(domain, record)
            print(f"{BLUE}{record} Records:{RESET}")
            for addr in answers:
                if record == 'NS':
                    print(f" - {WHITE}{addr.target.to_text()}{RESET}")
                else:
                    print(f" - {WHITE}{addr.to_text()}{RESET}")
            print()
    except Exception:
        pass

    print(f"{BLUE}--- Searching Subdomains via crt.sh ---{RESET}")
    find_subdomains_crtsh(domain)

# Module 6: Metadata Extraction
def metadata_extraction():
    try:
        import exifread
    except ImportError:
        print(f"{RED}exifread missing. Please install it: pip install exifread{RESET}")
        return

    print_blue_heading(
        "METADATA EXTRACTION",
        "Extract EXIF metadata from images or basic file metadata."
    )
    file_path = input("Enter path to file (image/document): ").strip()
    if not os.path.exists(file_path):
        print(f"{RED}File not found.{RESET}")
        return

    try:
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
            if not tags:
                print(f"{YELLOW}No EXIF metadata found.{RESET}")
                stats = os.stat(file_path)
                print(f"File size: {stats.st_size} bytes")
                print(f"Created: {datetime.fromtimestamp(stats.st_ctime)}")
                print(f"Modified: {datetime.fromtimestamp(stats.st_mtime)}")
                print("For deeper analysis of other file types, use ExifTool: https://exiftool.org/")
                return
            print(f"{GREEN}EXIF Metadata found:{RESET}")
            for t in sorted(tags):
                if t not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                    print(f"{BLUE}{t.ljust(30)}:{RESET} {tags[t]}")
    except Exception as e:
        print(f"{RED}Error processing file: {e}{RESET}")

# Module 7: Google Dorking
def google_dorking():
    print_blue_heading(
        "GOOGLE DORKING",
        "Use advanced Google search operators (examples provided)."
    )
    examples = [
        'site:example.com confidential',
        'filetype:pdf "internal use only"',
        'intitle:"index of" passwords',
        'inurl:admin inurl:login',
        'intext:"internal use only"'
    ]
    print("Examples:")
    for e in examples:
        print(f"  {BLUE}{e}{RESET}")
    dork = input("Enter your custom dork query: ").strip()
    if not dork:
        print(f"{RED}No dork entered.{RESET}")
        return
    print("Opening Google search...")
    webbrowser.open(f"https://www.google.com/search?q={dork}")

# Module 8: Wayback Machine Lookup
def wayback_machine_lookup():
    print_blue_heading(
        "WAYBACK MACHINE LOOKUP",
        "Retrieve historical snapshots of a URL."
    )
    url = input("Enter URL (include http:// or https://): ").strip()
    if not url or not url.startswith(('http://','https://')):
        print(f"{RED}Invalid URL.{RESET}")
        return
    user_agent = "MASTER-OSINT-TOOL/1.0 (+https://github.com/yourusername/yourtool)"
    try:
        api = WaybackMachineCDXServerAPI(url, user_agent)
        snaps = list(api.snapshots())
        if not snaps:
            print(f"{YELLOW}No snapshots found.{RESET}")
            return
        print(f"Found {len(snaps)} snapshots (showing up to 10):")
        for i, snap in enumerate(snaps):
            if i >= 10:
                break
            try:
                ts = datetime.strptime(snap.timestamp, "%Y%m%d%H%M%S")
                tsf = ts.strftime("%Y-%m-%d %H:%M:%S")
            except:
                tsf = snap.timestamp
            print(f"- {BLUE}{snap.archive_url}{RESET} (Captured: {tsf}, Status: {snap.statuscode})")
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")

# Module 9: IP Geolocation & Blacklist Check
def ip_geolocation_blacklist():
    print_blue_heading(
        "IP GEOLOCATION & BLACKLIST CHECK",
        "Find location and abuse data for IP."
    )
    ip = input(f"{BLUE}Enter IP address: {RESET}").strip()
    if not ip:
        print(f"{RED}No IP entered.{RESET}")
        return
    try:
        import ipaddress
        ipaddress.ip_address(ip)
    except:
        print(f"{RED}Invalid IP address.{RESET}")
        return
    try:
        geo_resp = requests.get(f"https://ipinfo.io/{ip}/json")
        geo = geo_resp.json()
        if geo_resp.status_code != 200:
            print(f"{RED}Geo lookup failed.{RESET}")
            return
        for label in ("Ip","Hostname","City","Region","Country","Loc","Org","Postal","Timezone"):
            print(f"{BLUE}{label.ljust(14)}:{RESET} {WHITE}{geo.get(label.lower(),'N/A')}{RESET}")
    except Exception as e:
        print(f"{RED}Geo lookup error: {e}{RESET}")
        return

    print(f"\n{BLUE}AbuseIPDB Report:{RESET}\n")
    abuseipdb_api_key = "YOUR_ABUSEIPDB_API_KEY"
    if abuseipdb_api_key == "YOUR_ABUSEIPDB_API_KEY":
        print(f"{YELLOW}AbuseIPDB API key not set. Skipping report.{RESET}")
    else:
        headers = {'Accept': 'application/json', 'Key': abuseipdb_api_key}
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json().get('data', {})
                score = data.get('abuseConfidenceScore', 0)
                reports = data.get('totalReports', 0)
                print(f"{'Abuse Confidence Score:':<25} {RED if score > 0 else GREEN}{score}%{RESET}")
                print(f"{'Total Reports (last 90 days):':<25} {RED if reports > 0 else GREEN}{reports}{RESET}")
                status = "Potentially Malicious IP" if score > 0 else "No significant abuse reports."
                color = RED if score > 0 else GREEN
                print(f"{'Status:':<7} {color}{status}{RESET}\n")
                if score > 0:
                    for rep in data.get('reports', [])[:3]:
                        print(f" - {WHITE}{rep.get('comment','N/A')} (Reported at {rep.get('reportedAt','N/A')}){RESET}")
                    if len(data.get('reports', [])) > 3:
                        print(f"   ... and {len(data['reports'])-3} more")
            else:
                print(f"{RED}API error HTTP {resp.status_code}{RESET}")
        except Exception as e:
            print(f"{RED}Error fetching AbuseIPDB: {e}{RESET}")

# Module 10: Website Metadata & Entity Scraper
def website_metadata_and_entity_scraper():
    print_blue_heading(
        "WEBSITE METADATA & ENTITY SCRAPER",
        "Extract title, meta tags, emails, persons, locations from URLs in 'urls.txt'. Requires Spacy."
    )
    if not SPACY_ENABLED:
        print(f"{YELLOW}Warning: Spacy model not loaded. Skipping entity extraction.{RESET}")
    try:
        with open("urls.txt") as f:
            urls = [line.strip() for line in f if line.strip()]
    except:
        print(f"{RED}Failed to read 'urls.txt'. Create it in this folder with one URL per line.{RESET}")
        return
    headers = {"User-Agent": "MASTER-OSINT-TOOL/1.0 (+https://github.com/yourusername/yourtool)"}

    def extract_emails(text):
        return sorted(set(re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text, re.I)))

    def extract_entities(text, labels):
        if not SPACY_ENABLED:
            return []
        doc = SPACY_NLP(text)
        return sorted(set(ent.text for ent in doc.ents if ent.label_ in labels))

    results = {}
    for url in urls:
        print(f"\nScraping: {BLUE}{url}{RESET}\n")
        try:
            r = requests.get(url, headers=headers, timeout=15)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, 'html.parser')

            title = soup.title.string.strip() if soup.title else "N/A"
            meta_tags = {}
            for m in soup.find_all("meta"):
                if "content" in m.attrs and ("name" in m.attrs or "property" in m.attrs):
                    key = m.attrs.get("name") or m.attrs.get("property")
                    meta_tags[key.lower()] = m.attrs["content"]

            emails = extract_emails(r.text)
            visible = soup.get_text(separator=" ", strip=True)
            names = extract_entities(visible, ["PERSON"])
            locations = extract_entities(visible, ["GPE", "LOC"])

            results[url] = dict(title=title, meta_tags=meta_tags, emails=emails, names=names, locations=locations)

            # Make label white and counts blue here
            print(f"Title: {WHITE}{title}{RESET}")
            print(f"{WHITE}Meta tags found:{RESET} {BLUE}{len(meta_tags)}{RESET}")
            print(f"{WHITE}Emails found:{RESET} {BLUE}{len(emails)}{RESET}")
            print(f"{WHITE}Names found:{RESET} {BLUE}{len(names)}{RESET}")
            print(f"{WHITE}Locations found:{RESET} {BLUE}{len(locations)}{RESET}")

        except Exception as e:
            print(f"{RED}Error scraping {url}: {e}{RESET}")
            results[url] = {"error": str(e)}
    try:
        with open("metadata_output.json", "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        print(f"\n{GREEN}Scraping complete. Data saved to metadata_output.json{RESET}")
    except Exception as e:
        print(f"{RED}Error saving results: {e}{RESET}")

# Module 11: Phone Number Investigation
def phone_number_lookup():
    if not PHONENUMBERS_ENABLED:
        print(f"{RED}phonenumbers module missing. Run pip install phonenumbers{RESET}")
        return

    example_num = f"{BLUE}+14085551234{RESET}"
    print_blue_heading(
        "PHONE NUMBER INVESTIGATION",
        f"Validate a phone number and generate Google dorks for OSINT.\nExample: {example_num}"
    )
    number = input("Enter phone number (incl. country code): ").strip()
    if not number:
        print(f"{RED}No input.{RESET}")
        return
    try:
        parsed = phonenumbers.parse(number, None)
        valid = phonenumbers.is_valid_number(parsed)
        possible = phonenumbers.is_possible_number(parsed)

        if not possible:
            print(f"{RED}Number is not possible.{RESET}")
            return

        print(f"Valid: {WHITE}{BLUE}{'Yes' if valid else 'No'}{RESET}")
        print(f"International: {WHITE}{BLUE}{phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}{RESET}")
        print(f"National: {WHITE}{BLUE}{phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)}{RESET}")
        print(f"Country/Location: {WHITE}{BLUE}{geocoder.description_for_number(parsed, 'en')}{RESET}")
        print(f"Carrier: {WHITE}{BLUE}{carrier.name_for_number(parsed, 'en')}{RESET}")
        type_num = number_type(parsed)
        types_map = {
            0: "Unknown", 1: "Fixed Line", 2: "Mobile", 3: "Fixed Line or Mobile", 4: "Toll Free",
            5: "Premium Rate", 6: "Shared Cost", 7: "VoIP", 8: "Personal Number", 9: "Pager", 10: "UAN"
        }
        print(f"Type: {WHITE}{BLUE}{types_map.get(type_num, 'Unknown')}{RESET}")

        print(f"\n{BLUE}Suggested Google Dorks:{RESET}\n")
        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        nat = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        e164_clean = re.sub(r'\D', '', e164)
        nat_clean = re.sub(r'\D', '', nat)

        print(f'  "{BLUE}{e164}{RESET}" OR "{BLUE}{nat}{RESET}"')
        print(f'  "{BLUE}{e164_clean}{RESET}" OR "{BLUE}{nat_clean}{RESET}"')

    except Exception as e:
        print(f"{RED}Error parsing: {e}{RESET}")

# Module 12: Reverse Image Search
def reverse_image_search():
    print_blue_heading(
        "REVERSE IMAGE SEARCH",
        "Use these popular reverse image search engines."
    )
    engines = {
        "Google Images": "https://images.google.com/",
        "TinEye": "https://tineye.com/",
        "Yandex": "https://yandex.com/images/",
        "Bing Visual Search": "https://www.bing.com/images/discover",
        "Baidu Image Search": "https://image.baidu.com/",
        "SauceNAO": "https://saucenao.com/",
        "ImgOps": "https://imgops.com/"
    }
    for name, url in engines.items():
        print(f"{BLUE}{name.ljust(18)}:{RESET} {WHITE}{url}{RESET}")
    input("\nPress Enter to return to menu...")

# Module 13: Geospatial Intelligence (GEOINT)
def geospatial_intelligence():
    print_blue_heading(
        "GEOSPATIAL INTELLIGENCE (GEOINT)",
        "View any location coordinates or place using Google Satellite Maps and OpenStreetMap."
    )
    input_data = input("Enter GPS coordinates (latitude,longitude) or location name/address: ").strip()
    if not input_data:
        print(f"{RED}No input entered. Returning to menu.{RESET}")
        return

    lat, lon = None, None
    coords_ok = False
    try:
        parts = [p.strip() for p in input_data.split(',')]
        if len(parts) == 2:
            lat = float(parts[0])
            lon = float(parts[1])
            if -90 <= lat <= 90 and -180 <= lon <= 180:
                coords_ok = True
    except Exception:
        coords_ok = False

    if coords_ok:
        print(f"{GREEN}Valid coordinates detected: {lat}, {lon}{RESET}")
        google_sat_url = f"https://www.google.com/maps/@{lat},{lon},15z/data=!5m1!1e4"
        osm_url = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}"
    else:
        print(f"{YELLOW}Input not recognized as valid coordinates, treating as location query...{RESET}")
        query = input_data.replace(' ', '+')
        google_sat_url = f"https://www.google.com/maps/search/?api=1&query={query}&layer=c"
        osm_url = f"https://www.openstreetmap.org/search?query={query}"

    print(f"\n{BLUE}Opening Google Satellite Map:{RESET} {google_sat_url}")
    webbrowser.open(google_sat_url)

    print(f"{BLUE}Opening OpenStreetMap:{RESET} {osm_url}")
    webbrowser.open(osm_url)

    print(f"\n{GREEN}Geospatial views opened in your default browser.{RESET}")

# Main Execution Loop
def main():
    print_logo()
    while True:
        print_menu()
        choice = input_menu_choice()
        try:
            ci = int(choice)
        except ValueError:
            print(f"{RED}Invalid input. Enter a number between 1 and {len(print_menu_options())}.{RESET}")
            continue

        if ci == 1:
            image_geolocation()
        elif ci == 2:
            social_media_investigation()
        elif ci == 3:
            email_analysis()
        elif ci == 4:
            email_lookup_and_verification()
        elif ci == 5:
            domain_investigation()
        elif ci == 6:
            metadata_extraction()
        elif ci == 7:
            google_dorking()
        elif ci == 8:
            wayback_machine_lookup()
        elif ci == 9:
            ip_geolocation_blacklist()
        elif ci == 10:
            website_metadata_and_entity_scraper()
        elif ci == 11:
            phone_number_lookup()
        elif ci == 12:
            reverse_image_search()
        elif ci == 13:
            geospatial_intelligence()
        elif ci == 14:
            print(f"\n{BLUE}Thanks for using MASTER OSINT FOR BEGINNERS! Stay ethical and keep learning!{RESET}\n")
            sys.exit(0)
        else:
            print(f"{RED}Invalid choice. Choose between 1 and {len(print_menu_options())}.{RESET}")

        print("\n" + "="*80 + "\n")

if __name__ == "__main__":
    main()

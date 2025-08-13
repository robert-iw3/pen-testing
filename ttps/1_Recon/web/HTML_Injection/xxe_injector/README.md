<br>
<center><img src="https://i.postimg.cc/8cXFcr3Z/HTMLI.png"></center>
<br>

## Features:

- **HTTP Parameter Pollution (HPP)**
- **HTML Injection (HTMLi)**
- **XML External Entity (XXE) Injection**

# Installation
```bash
pip install -r requirements.txt
```

replace collaborator url line 26: COLLABORATOR_URL = "your-collaborator-url.com"
replace redirct url line 353: "https://www.example.com"

## Usage

`python htmli.py -u <target_url> [--hpp] [--htmli] [--xxe]`

**Arguments:**

- `-u`, `--url`: The target website URL.
- `--hpp`:  Enable HTTP Parameter Pollution testing.
- `--htmli`: Enable HTML Injection testing.
- `--xxe`: Enable XXE Injection testing.

**Examples:**

- **Test for all vulnerabilities:**
  ```bash
  python htmli.py -u "https://example.com" --hpp --htmli --xxe

## Important Notes
Use this tool ethically and responsibly.


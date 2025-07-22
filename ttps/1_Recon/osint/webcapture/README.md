# 🕸️ WEBCAPTURE

> A stealthy website screenshotting tool for recon, automation, and visual intelligence gathering.

## 🔍 Overview

`WEBCAPTURE` is a simple yet powerful utility for capturing full-page or viewport screenshots of websites. It’s built for OSINT analysts, bug bounty hunters, and security researchers who need quick visual snapshots of live web targets. Useful in reconnaissance, monitoring, or archiving website states.
<video src="https://github.com/drackyjr/WEBCAPTURE/blob/main/Screencast%20From%202025-06-16%2019-45-13.mp4" controls></video>


## 🚀 Features

- 📸 Capture full-page or viewport screenshots
- 🧠 Fast and minimal footprint
- ⚙️ CLI-based usage for automation
- 🕵️‍♂️ Ideal for recon workflows and threat hunting

## 🛠️ Requirements

- Python 3.8+
- Linux / Windows / MacOS
- Google Chrome or Chromium (headless mode)
- `pip` for installing dependencies

## 🧪 Installation

```bash
podman build -t webcapture .
podman run -it --name webcapture webcapture
```

### Usage 
```bash
python3 main.py --url <URL> --emails --phones --links --whois --ipinfo --subdomains
```




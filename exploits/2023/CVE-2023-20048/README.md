
# FuegoTest

FuegoTest is a Command Line Interface (CLI) tool designed to detect devices potentially vulnerable to CVE-2023-20048 in Cisco Firepower Management Center (FMC). Utilizing the rich library, FuegoTest provides an enhanced user experience with progress bars and styled text for terminal output.

## Features

- Authenticate with Cisco FMC using provided credentials.
- Fetch and list devices managed by the FMC.
- Detect devices potentially vulnerable to CVE-2023-20048.
- Enhanced terminal output with progress bars and styled text.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- Python 3.6 or higher
- pip for installing dependencies

## Installation

To install FuegoTest, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/FuegoTest.git
   ```
2. Navigate to the FuegoTest directory:
   ```bash
   cd FuegoTest
   ```
3. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

To use FuegoTest, you'll need to provide the URL, username, password, and domain ID of your Cisco FMC. Run the following command and follow the prompts:

```bash
python fuegotest.py detect
```

You can also provide the details as options:

```bash
python fuegotest.py detect --fmc-url=<FMC_URL> --fmc-user=<FMC_USER> --fmc-pass=<FMC_PASS> --domain-id=<DOMAIN_ID>
```

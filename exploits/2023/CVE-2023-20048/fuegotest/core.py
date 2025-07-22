import requests
import logging

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class FuegoTest:
    def __init__(self, fmc_url, fmc_user, fmc_pass, domain_id):
        self.fmc_url = fmc_url
        self.session = requests.Session()
        self.session.verify = False
        self.fmc_user = fmc_user
        self.fmc_pass = fmc_pass
        self.domain_id = domain_id
        self.logger = logging.getLogger('FuegoTest')

    def authenticate(self):
        """Authenticate with the FMC and set the session token."""
        token_url = f"{self.fmc_url}/api/fmc_platform/v1/auth/generatetoken"
        response = self.session.post(token_url, auth=(self.fmc_user, self.fmc_pass))
        if response.status_code == 204:
            self.session.headers.update({
                'X-auth-access-token': response.headers['X-auth-access-token']
            })
            self.logger.info("Authentication successful.")
        else:
            self.logger.error("Failed to authenticate.")
            raise Exception("Authentication failed with status code: {}".format(response.status_code))

    def get_devices(self):
        """Retrieve the list of devices managed by FMC."""
        devices_url = f"{self.fmc_url}/api/fmc_config/v1/domain/{self.domain_id}/devices/devicerecords"
        response = self.session.get(devices_url)
        if response.status_code == 200:
            return response.json().get('items', [])
        else:
            self.logger.error("Failed to retrieve devices.")
            return []


    def detect_vulnerable_devices(self, progress, task):
        """Detect devices potentially vulnerable to CVE-2023-20048, with progress updates."""
        self.authenticate()
        devices = self.get_devices()
        vulnerable_devices = []

        for device in devices:
            if device['type'] == 'device' and device['metadata']['softwareVersion'] in ['6.2.3.18', '6.4.0.16', '6.6.7.1']:
                vulnerable_devices.append(device['name'])
                logging.info(f"Device {device['name']} is potentially vulnerable to CVE-2023-20048.")
            progress.update(task, advance=1/len(devices))
    
        return vulnerable_devices


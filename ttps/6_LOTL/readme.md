https://lolbas-project.github.io/#

## Living off the Land (Sneaky, Sneaky)

"Living Off the Land" (LOTL) refers to a cyberattack technique where attackers use legitimate tools and software already present on a target system to perform malicious actions, rather than installing new malware. This allows them to blend in with legitimate system activity, making it harder to detect their malicious actions.
Here's a more detailed explanation:

    Definition:
    LOTL attacks involve leveraging existing software and functionalities within the target system to achieve malicious goals. Attackers use pre-existing tools like command-line utilities (e.g., cmd.exe, PowerShell), scheduling utilities, and other native functionalities.

Why it's used:
LOTL techniques are often preferred by attackers because they are:

    Cheaper and Easier: They don't require the development or distribution of new malware, which can be resource-intensive.

More Effective: They can be more effective in bypassing security measures that rely on signature-based detection of malware.
Less Obvious: They can blend in with legitimate system activity, making it difficult to detect their malicious actions.

Examples of LOTL Techniques:

    Command-Line Exploitation: Attackers use legitimate command-line tools to execute malicious commands.

Scheduling and Automation Tools: They modify or exploit scheduled tasks to run malicious code at specific times.
Registry Modifications: They alter the Windows Registry to enable persistent access to the system.
System Information Tools: They use legitimate tools like systeminfo to gather information about the target system.

Defense against LOTL:

    Behavior-Based Detection: Security systems need to be able to detect unusual or malicious behavior, even if it's using legitimate tools.

Log Analysis: Analyzing system logs for unusual activity and patterns can help identify LOTL attacks.
Intrusion Detection Systems: These systems can help identify and block malicious activity that is not using known malware signatures.
Training and Awareness: Educating users about potential threats and how to identify suspicious activity can help prevent attacks.
Endpoint Detection and Response: These solutions can provide advanced detection and response capabilities, including identifying and neutralizing LOTL attacks.

In essence, "Living Off the Land" is a stealthy attack method that relies on the attacker's ability to blend in with legitimate system activity, making it a significant challenge for cybersecurity defenses.

##

A curated list of awesome LOLBins, GTFO projects, and similar 'Living Off the Land' security resources.

## Contents

- [Argument Injection Vectors](#argument-injection-vectors)
- [Bootloaders](#bootloaders)
- [Certificates](#certificates)
- [Evasions](#evasions)
- [FileSec](#filesec)
- [GTFO](#gtfo)
- [Hijack Libraries](#hijack-libraries)
- [LOFL Project](#lofl-project)
- [LOLApps](#lolapps)
- [LOLBAS](#lolbas)
- [LOLAD](#lolad)
- [LOLDrivers](#loldrivers)
- [LOOBins](#loobins)
- [LOLESXi](#lolesxi)
- [LOLRMM](#lolrmm)
- [LOTHardware](#lothardware)
- [LOTP](#lotp)
- [LOTS Project](#lots-project)
- [MalAPI](#malapi)
- [Persistence Information](#persistence-information)
- [Project Lost](#project-lost)
- [Sploitify](#sploitify)
- [WADComs](#wadcoms)
- [WTFBins](#wtfbins)

## Argument Injection Vectors

- [Argument Injection Vectors](https://sonarsource.github.io/argument-injection-vectors/) - A curated list of exploitable options for argument injection bugs.

## Bootloaders

- [Bootloaders](https://www.bootloaders.io/) - A comprehensive resource on bootloaders and their security implications.

## Certificates

- [LoLcerts](https://github.com/WithSecureLabs/lolcerts) - Living Off The Leaked Certificates - A collection of abused code signing certificates.

## Evasions

- [Evasions](https://evasions.checkpoint.com/) - A resource for understanding and implementing various evasion techniques.

## FileSec

- [FileSec](https://filesec.io/) - A comprehensive database of file extensions and their associated security risks.

## GTFO

- [GTFOArgs](https://gtfoargs.github.io/) - A collection of Unix binaries that can be exploited through argument injection.
- [GTFOBins](https://gtfobins.github.io/) - A curated list of Unix binaries that can be used to bypass local security restrictions.

## Hijack Libraries

- [HijackLibs](https://hijacklibs.net/) - A collection of DLL hijacking techniques and vulnerable libraries.

## LOFL Project

- [LOFL Project](https://lofl-project.github.io/) - Living Off Foreign Land - A collection of unconventional persistence techniques.

## LOLApps

- [LOLApps](https://lolapps-project.github.io/#) - Living Off The Land Applications - Legitimate applications that can be abused for malicious purposes.

## LOLBAS

- [LOLBAS](https://lolbas-project.github.io/#) - Living Off The Land Binaries, Scripts and Libraries for Windows.

## LOLAD

- [LOLAD](https://lolad-project.github.io/) - Living Off the Land in Active Directory - A collection of techniques for exploiting Active Directory environments.

## LOLDrivers

- [LOLDrivers](https://www.loldrivers.io/) - A collection of vulnerable drivers that can be exploited.

## LOOBins

- [LOOBins](https://www.loobins.io/) - Living Off The Orchard Binaries - macOS/OSX binaries that can be abused.

## LOLESXi

- [LOLESXi](https://lolesxi-project.github.io/LOLESXi/) - Living Off the Land ESXi - A comprehensive list of binaries/scripts natively available in VMware ESXi that adversaries have utilized in their operations.

## LOLRMM

- [LOLRMM](https://lolrmm.io/) - A resource for understanding and utilizing Remote Monitoring and Management (RMM) tools in cybersecurity operations.

## LOTHardware

- [LOTHardware](https://lothardware.com.tr/) - Living Off The Hardware - Hardware-based attack techniques and resources.

## LOTP

- [LOTP](https://boostsecurityio.github.io/lotp/) - Living Off The Pipeline - CI/CD pipeline abuse techniques.

## LOTS Project

- [LOTS Project](https://lots-project.com/) - Living Off Trusted Sites - Legitimate domains that can be abused by attackers.

## MalAPI

- [MalAPI](https://malapi.io/) - A comprehensive Windows API reference for malware analysis and red teaming.

## Persistence Information

- [Persistence Information](https://persistence-info.github.io/) - A curated resource that compiles various Windows persistence techniques to aid in detection and mitigation strategies.

## Project Lost

- [Project Lost](https://0xanalyst.github.io/Project-Lost/) - A collection of lesser-known techniques and tools for red teaming and penetration testing.

## Sploitify

- [Sploitify](https://sploitify.haxx.it/) - A database of exploits and vulnerabilities for various systems and applications.

## WADComs

- [WADComs](https://wadcoms.github.io/) - A collection of one-liners and commands for Windows Active Directory environments.

## WTFBins

- [WTFBins](https://wtfbins.wtf/) - A comprehensive repository of suspicious Windows binaries and their behaviors.
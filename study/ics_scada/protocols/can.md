# CAN

| Protocol | CAN |
|---|---|
| Name | CAN |
| Aliases | CANbus, CANopen, CAN-FD |
| Description | Communication protocol enabling data exchange between electronic components in vehicles |
| Keywords | CANbus |
| Specifications | [ISO-11898](https://www.iso.org/standard/63648.html) |
| Wireshark dissector | [packet-canopen.c](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-canopen.c) |
| Scapy layer | [can.py](https://github.com/secdev/scapy/blob/master/scapy/layers/can.py) |
| Related CVE | [CVE-2010-2959](https://nvd.nist.gov/vuln/detail/CVE-2010-2959), [CVE-2010-3874](https://nvd.nist.gov/vuln/detail/CVE-2010-3874), [CVE-2016-9337](https://nvd.nist.gov/vuln/detail/CVE-2016-9337), [CVE-2017-14937](https://nvd.nist.gov/vuln/detail/CVE-2017-14937), [CVE-2020-8539](https://nvd.nist.gov/vuln/detail/CVE-2020-8539), [CVE-2023-29389](https://nvd.nist.gov/vuln/detail/CVE-2023-29389) |

## Documentations
- [DBC Specification](https://github.com/stefanhoelzl/CANpy) - A description of CAN database layout
- [Linux SocketCAN documentation](https://www.kernel.org/doc/html/latest/networking/can.html) - kernel.org
## Articles
- [CAN Injection: keyless car theft](https://kentindell.github.io/2023/04/03/can-injection/) - CANIS Automative Labs CTO blog (2023)
- [CAN-FD - The basic idea](https://www.can-cia.org/can-knowledge/can-fd-the-basic-idea) - CAN in Automation
- [Click here to download more cars](https://djnn.sh/posts/car_hacking) - djnn
## Conferences
- [#HITBCyberWeek D1T2 - Car Hacking: Practical Guide To Automotive Security - Yogesh Ojha](https://www.youtube.com/watch?v=jn0bCFB_q30) - @  Hack In The Box (2020)
- [#HITBCyberWeek D2T2 - RAMN: Resistant Automotive Miniature Network](https://www.youtube.com/watch?v=5N1ZmWXyws8) - @  Hack In The Box (2020)
- [(Pen)Testing Vehicles with CANToolz](https://www.youtube.com/watch?v=-p47IYz-H-k) - Alexey Sintsov @ Black Hat Europe (2016)
- [Abusing CAN Bus Spec for DoS in Embedded Systems](https://www.youtube.com/watch?v=okrzUNDLgbo) - Martin Petran @ DEF CON 31 Car Hacking Village (2023)
- [Advanced CAN Injection Techniques for Vehicle Networks](https://www.youtube.com/watch?v=4wgEmNlu20c) - Charlie Miller & Chris Valasek @ Black Hat USA (2016)
- [Adventures in Building a CAN Bus Sniffer](https://www.youtube.com/watch?v=ku2_t9EX-pM) - Andrey Voloshin @ Hack In The Box (2020)
- [All Aboard the CAN Bus or Motorcycle](https://www.youtube.com/watch?v=YSApvBDIVCM) - Derrick @ DEF CON Safe Mode Car Hacking Village (2020)
- [Backdooring & Remotely Controlling Cars](https://www.youtube.com/watch?v=1at33wF6fLE) - Sheila A. Berta & Claudio Carraciolo @ Hack In The Box (2018)
- [Backdooring of Real Time Automotive OS Devices](https://www.youtube.com/watch?v=Z2Dgt7XhHGs) - @ Black Hat (2022)
- [CAN Bus in Aviation Investigating CAN Bus in Avionics](https://www.youtube.com/watch?v=bydy7lbFyFU) - Patrick Kiley @ DEF CON 27 Aviation Village (2019)
- [CANsee: An Automobile Intrusion Detection System](https://www.youtube.com/watch?v=XBg8xhK7L0w) - Jun Li @ Hack In The Box (2016)
- [Canspy: A Platform for Auditing Can Devices](https://www.youtube.com/watch?v=1hPRcdwQioc) - Jonathan-Christofer Demay & Arnaud Lebrun @ Black Hat USA (2016)
- [CANSPY: Auditing CAN Devices](https://www.youtube.com/watch?v=vTsdxNGS_xc) - Jonathan Christofer Demay, Arnaud Lebrun @ DEF CON 24 (2016)
- [Cantact: An Open Tool for Automative Exploitation](https://www.youtube.com/watch?v=HzDW8ptMkDk) - Eric Evenchick @ Black Hat Asia (2016)
- [canTot A CAN Bus Hacking Framework](https://www.youtube.com/watch?v=OBC0v5KDcJg) - Jay Turla @ DEF CON 30 Car Hacking Village (2022)
- [Deep Learning on CAN BUS](https://www.youtube.com/watch?v=1QSo5sOfXtI) - Jun Li @ DEF CON 24 Car Hacking Village (2016)
- [Free-Fall: Hacking Tesla from Wireless to CAN Bus](https://www.youtube.com/watch?v=0w8J9bmCI54) - Ling Liu, Sen Nie & Yuefeng Du @ Black Hat USA (2017)
- [Fuzzing CAN / CAN FD ECU's and Network](https://www.youtube.com/watch?v=IMZ8DD4lTAY) - Samir Bhagwat @ DEF CON 29 Car Hacking Village (2021)
- [Hopping on the CAN Bus](https://www.youtube.com/watch?v=U1yecKUmnFo) - Eric Evenchick @ Black Hat USA (2015)
## Papers
- [A Fuzz Testing Methodology for Cyber-security Assurance of the Automotive CAN Bus](https://pure.coventry.ac.uk/ws/portalfiles/portal/37979533/Fowler_PhD.pdf) - Daniel S. Fowler, Coventry University (2019)
## Tools
- [cantools](https://github.com/cantools/cantools) - Python library to play with CAN databases & messages
- [opendbc](https://github.com/commaai/opendbc) - A list of CAN databases retrieved from reverse-engineered cars
- [python-can](https://github.com/hardbyte/python-can) - Python library to plug to various CAN connectors

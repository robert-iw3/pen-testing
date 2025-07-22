# Qakbot 30 September 2022

## Intro

Three days ago a friend of mine received a phishing e-mail with a link (https[:]//lynxus[.]com/usq/refeidpisnretse) containing a zip file protected by the password "U492". 

<img width="1262" alt="0" src="https://user-images.githubusercontent.com/15001354/193664727-69ee625c-3a4d-4eea-8e71-5e718b625086.png">

Inside the zip there is an ISO called Learn#7435.iso containing a shortcut to the following malicious script:

~~~
// observablyCleaned
var undisruptedPuzzles = "rund DllRegis";

// ShellExecute
var bridgeheadsLibels = new ActiveXObject("shell.application").shellexecute("assaulting\\redressingLamentations.cmd", undisruptedPuzzles, "", "open", 0);
~~~

<img width="1134" alt="1" src="https://user-images.githubusercontent.com/15001354/193664786-75664000-6658-4582-9d27-258bd18f9d39.png">


The script uses ActiveXObject in order to execute another script called redressingLamentations.cmd (in the ISO) by passing the arguments "rund" and "DllRegis". 

Following the redressingLamentations.cmd script:

~~~
@echo off

	set a=ll
	set e=32

	:: tankageLicentiously
	%1%a%%e% assaulting\tiddler.dat,%2terServer

exit
~~~

It runs the command rundll32 assaulting\tiddler.dat,DllRegisterServer in order to start the malicious DLL.

## First Stage

After a bit of analysis, I wrote this simple script to extract the loader in order to practice a bit with python. 
The two strings used to generate the key are taken dynamically, the shellcode is taken dynamically by using the size offset that is hardcoded.


The malicious DLL was uploaded to [Malware Bazaar](https://bazaar.abuse.ch/sample/5b54f57dbaa74fa589afb2d26d6c6b39e0c2930bd88fea3172556ce96b3eb959/) by JAMESWT_MHT.


These two strings are used to generate the key:

* ewZOSoNXdJTjGtfGFtJwDGnslgItKrqSOoXTBEUIeNsATwlqubQMeKZByuBEOxjyadypZOaxQyRosZjVcChW
* gjdhkdfgkjsdghfkjsdhkjslfdghsdkjl

The key is:

* 7fafab656017bf33b9606982e6a6f277

HASHES:

* SHA256: 5B54F57DBAA74FA589AFB2D26D6C6B39E0C2930BD88FEA3172556CE96B3EB959

* SHA1: 4aa4e28cd07e218e45ec60942c53d82c3f50fea7

* MD5: 7754a35deec807d757f79165ba17708d


### Unpacking

Extracted DLL from tiddler.da, you can find it on [Malware Bazaar](https://bazaar.abuse.ch/sample/8b08c031d365a0b4d032c6e51bf773655e15795fe3eabcd3fa6487ffe9f3d6b3/).

Qakbot config

<img width="395" alt="Screenshot 2022-10-11 at 18 11 43" src="https://user-images.githubusercontent.com/15001354/195144484-7ca59ab7-db7a-4d28-9899-99f629ba295a.png">

10=BB

3=1664535088

HASHES:

* SHA256: 8b08c031d365a0b4d032c6e51bf773655e15795fe3eabcd3fa6487ffe9f3d6b3

* SHA1: cd0528db38e743c619341d3a542748be86d9ba72

* MD5: b8fb226a54197955a05705be00ff2d07


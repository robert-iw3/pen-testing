# HtmlSmuggling

&emsp; The HTML smuggling method is highly evasive. It could bypass standard perimeter security controls like web proxies and email gateways, which only check for suspicious attachments like EXE, DLL, ZIP, RAR, DOCX or PDF

&emsp; **1) HtmlSmuggling.py :** Embeds the selected binary file (exe, dll, docx, pdf, etc) into the Javascript file. Obfuscates Javascript functions. This makes it difficult to decode javascript functions.

&emsp; "HtmlSmuggling" attack type is an attack type affected by browser settings. In addition, EXE, DLL type files downloaded from the internet can be blocked by smartscreen. However, PDF, DOCX attacks are more successful.

![htmlsmuggling](https://user-images.githubusercontent.com/71177413/174580595-4ade6473-7d2a-4ef6-ab98-c788fbd5d3e5.JPG)

Using the Script
---

**[Command]**
```
>> HtmlSmuggling.py filename filepath
```
&emsp; **filename:** Browser refers to the file name to be given to the file to be downloaded. It is the file name that will be seen in the browser and the downloaded folder.

&emsp; **filepath:** The path of the file to be downloaded

**[Command Example]**
```
>> HtmlSmuggling.py MicrosoftOffice.exe c:\Users\user0\Desktop\malware.exe
>> HtmlSmuggling.py Office365.dll c:\Users\user0\Desktop\malware.dll
>> HtmlSmuggling.py application.pdf c:\Users\user0\Desktop\malware.pdf
>> HtmlSmuggling.py application.docx c:\Users\user0\Desktop\malware.docx
```

---

 **[ScreenShot 1]**
![b1](https://user-images.githubusercontent.com/71177413/174581941-8bc693dd-2d0c-4fa2-b1cc-900cbcd3fc0c.png)

**[ScreenShot 2]**
![a2](https://user-images.githubusercontent.com/71177413/174581963-d49e485a-b0e8-4fb1-a56c-5e85e3d3563e.png)

**[ScreenShot 3]**
![a3](https://user-images.githubusercontent.com/71177413/174581996-5c21783d-9acd-4411-bcde-b74287128ab2.png)

**[ScreenShot 4]**
![a4](https://user-images.githubusercontent.com/71177413/174582053-c683d209-ed76-449a-9897-812fa9f99edb.png)

**[ScreenShot 4]**
![a5](https://user-images.githubusercontent.com/71177413/174582090-a9d438ac-a27a-49a0-a4d4-3eeae0e32f69.png)


Use within legal parameters. Shared for educational purposes.

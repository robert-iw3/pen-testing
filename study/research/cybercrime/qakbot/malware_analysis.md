# Qbot-Qakbot-Malware-Analysis

Qbot also known as Qakbot, is a comman banking trojan malware designed to steal passwords. The malware has been active since 2008 and used by financially motivated actors. Obot malware commonly delivered using phishing emails which contains malicious html file, that file embedded with zip password protected zip file.

## Malware Sample

> **MD5:**  5cb20a0bfc5e3e2ae8398b1840adf7ae

> **SHA256:**  f5c16248418a4f1fd8dff438b26b8da7f587b77db9e180a82493bae140893687

## Static Analysis

- Attackers sending HTML file as an attachment using email. 

- This HTML file has zip file inside it which is password protected.  

<img width="920" alt="image" src="https://user-images.githubusercontent.com/43460691/235127065-702b8389-d7ba-4ae4-a8be-b4941172050c.png">

- Once user open the HTML file password-protected **TXRTN_2636021.zip** file will download.

![image](https://user-images.githubusercontent.com/43460691/235129290-d3390667-4890-4c9c-99be-3587e24f5765.png)

### HTML Smuggling

- HTML smuggling is an method that helps atacker smuggle payload past content filters and firewalls by hiding malicious payloads inside of seemingly benign HTML file.

- On opening HTML file in vscode we can see how this HTML smuggling being done.

- There is very long base64encoded content packed into zip file and dropped into the device.

![image](https://user-images.githubusercontent.com/43460691/235132919-3d0bfad1-5120-4829-bfe6-33a573768c68.png)

## Dynamic Analysis

- On Unzipping the ZIP file using password shown in the HTML document, User will gets the ISO file.

![image](https://user-images.githubusercontent.com/43460691/235137423-744d4a8c-7a1f-4510-9124-eee408c7710a.png)


- On mounting the ISO, user see only the LNK(shortcut) file; rest of the files are hidden.

![image](https://user-images.githubusercontent.com/43460691/235137672-3e0630b8-d98b-4374-9c3a-294c3ec19b94.png)


- On checking the hidden files, there are four files inside it i.e, **.LNK(shortcut),calc.exe(Windlows Calculator) and two DLL files**.

- 102755.dll file  is an **Qbot Payload**.

![image](https://user-images.githubusercontent.com/43460691/235137912-f588ca1a-e534-4aa7-b294-1002dabd04cd.png)

- User clicking on shortcut file triggers the Qbot Malware infection by executing the **calc.exe** through the Command Prompt.

![image](https://user-images.githubusercontent.com/43460691/235138805-823bec11-f508-4642-9f84-27930876c461.png)

### DLL Sideloading

- Windows allows applications to load DLLs at runtime. Application canspecify the location of DLLs to  load by specifying full path, using DLL redirection, or by using an application manifest. If none or these methods are used, it attempts to locate the DLL by searching a predefined set of directories in a set order.

- In this analysis, When the shortcut loads the windows calculator, it automatically searches and attempts to load WindowsCodecsDLL file. It dose not check for the DLL in certain hard coded paths it will load any DLL file with the same name if placed in the same folder.

![image](https://user-images.githubusercontent.com/43460691/235376789-1118c9cc-168f-4cea-a369-9f82beb75444.png)

- After changing the data type of local veriales, We can see that this veriables actually consists of DLL name.

![image](https://user-images.githubusercontent.com/43460691/235324959-370acb0c-3d9c-4132-bbfd-b3d780e3663f.png)

- WindowsCodecs.dll checks for 64/32 bit process using GetenvironmentVeriableW() and GetcurrentProcess().

![image](https://user-images.githubusercontent.com/43460691/235325033-29048004-6211-4ac3-b213-270c46784299.png)

- WindowsCodecs.dll leaveraging regsvr32 via CreateProcessW to load the Obot DLL.

- Later, when Qbot payload executed it tries for persistence via schedule task.

![image](https://user-images.githubusercontent.com/43460691/235325272-c40c297a-585d-4cc4-a8c1-a9a5d52708ea.png)


## Flow-Chart :

![image](https://user-images.githubusercontent.com/43460691/235368241-5af48221-e0c9-4db4-9f01-fbefccd81219.jpeg)

## References : 

- AnyRun Sandbox - https://app.any.run/tasks/09b802b4-5fbe-487c-b361-efcc0742dab1/#

- MITRE : HTML Smuggling - https://attack.mitre.org/techniques/T1027/006/

- MITRE : DLL SideLoading - https://attack.mitre.org/techniques/T1574/002/








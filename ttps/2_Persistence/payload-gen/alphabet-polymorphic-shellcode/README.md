## AlphabeticalPolyShellGen: Generate an Alphabetical Polymorphic Shellcode



</br>

## How Does It Work

* First, the input shellcode is encoded using the same logic behind [Alphabetfuscation](https://github.com/Maldev-Academy/Alphabetfuscation), which is a shellcode obfuscation method that represents opcode bytes as ASCII. And since this method uses a random ASCII offset per byte, the encoded output differs on every run.
* The **first shellcode**, [g_AlphabeticalDecoder](https://github.com/Maldev-Academy/AlphabeticalPolyShellGen/blob/main/AlphabeticalPolyGen/Main.c#L236), is prepended with the encoded Alphabetical shellcode, after being configured with the required data for decoding.
* The `g_AlphabeticalDecoder` is then itself encoded using a simple XOR routine; [XorEncrypt](https://github.com/Maldev-Academy/AlphabeticalPolyShellGen/blob/main/AlphabeticalPolyGen/Main.c#L23).
* A **second shellcode** is _dynamically generated_ using the [GenerateRandomVariant](https://github.com/Maldev-Academy/AlphabeticalPolyShellGen/blob/main/AlphabeticalPolyGen/PolyShellcodeGen.h#L298C6-L298C27) function. This shellcode is responsible for decoding and passing code execution to `g_AlphabeticalDecoder`, which decodes the Alphabetical shellcode and executes it, alongside performing necessary memory cleanup logic.


</br>

> [!NOTE]
> The logic behind the `g_AlphabeticalDecoder` shellcode is located in the [AlphabeticalShellcodeDecode.asm](https://github.com/Maldev-Academy/AlphabeticalPolyShellGen/blob/main/AlphabeticalShellcodeDecode.asm) file.
> 
> The logic behind the XOR decoder shellcode is located in the [XorShellcodeDecode.asm](https://github.com/Maldev-Academy/AlphabeticalPolyShellGen/blob/main/XorShellcodeDecode.asm) file,.
 


</br>

## Usage:

* One can execute the [AlphabeticalPolyGen](https://github.com/Maldev-Academy/AlphabeticalPolyShellGen/tree/main/AlphabeticalPolyGen) program to generate a polymorphic shellcode variant of a specified shellcode:

```
AlphabeticalPolyGen.exe --i <Raw Shellcode File> --o <Output File Name>
```

* For testing, use the [LocalShellcodeExec.exe](https://github.com/Maldev-Academy/AlphabeticalPolyShellGen/tree/main/LocalShellcodeExec) program as follows:

```
LocalShellcodeExec.exe --i <Encoded Shellcode To Execute>
```


</br>


## Demo:

### 1. Building two variants of Metasploit's x64 calc.exe shellcode: 

<img width="1436" height="813" alt="image_2025-08-14_18-49-31" src="https://github.com/user-attachments/assets/412cd24c-33e9-4c03-bdcf-5fca40805062" />
<img width="1283" height="729" alt="image_2025-08-14_18-49-31 (2)" src="https://github.com/user-attachments/assets/044e4820-7f0f-4c10-aa60-a108c267b404" />

</br>
</br>

### 2. Examining these variants in a hex editor:

<img width="1154" height="854" alt="Screenshot 2025-08-14 185029" src="https://github.com/user-attachments/assets/0c677b7c-fcd2-4d5f-803d-d6bb980c7c31" />

</br>

### 3. Utilizing the [LocalShellcodeExec.exe](https://github.com/Maldev-Academy/AlphabeticalPolyShellGen/tree/main/LocalShellcodeExec) for testing:

<img width="1557" height="547" alt="Screenshot 2025-08-14 185200" src="https://github.com/user-attachments/assets/983ea399-becd-476d-a3b7-745a69af1121" />

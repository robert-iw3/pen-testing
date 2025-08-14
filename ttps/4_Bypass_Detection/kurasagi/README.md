# kurasagi

`kurasagi` is full POC of PatchGuard bypass for Windows 24H2, Build 26100.4351.

Kernel Patch Protection, also known as PatchGuard, is a security feature in Windows 11 that prevents unauthorized modifications to the kernel, enhancing system stability and security. It specifically targets attempts to patch the kernel, which can compromise the operating system. Kernel-mode hardware-enforced stack protection is another security feature, related to PatchGuard, that protects against stack buffer overflows and other memory attacks. 

## Changelog

(2025/08/03) **Caution**: Upgraded to 26100.4652. for 26100.4351 version bypass, refer to commit `80650b9cb71855042659137ecd8936f8a9336a61`.

## Disclaimers

1. **PLEASE USE IT FOR ONLY EDUCATIONAL PURPOSES!**
2. Do not turn on hypervisor-based security factors when running! (It will BSOD!)
3. Use [kdmapper](https://github.com/TheCruZ/kdmapper) for driver loading.
4. After `kurasagi` has been loaded, we just found there's some weird issue when you allocate pool with `NonPagedPoolExecute` (or `NonPagedPool`, it is same), it is not executable. I'll fix as soon as possible.


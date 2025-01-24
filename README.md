# Vulnerable-Driver-Manual-Mapper
This repository contains a complete C++ implementation of a custom Windows driver loader that leverages a vulnerable driver to bypass security features and load custom kernel-mode drivers. The core idea for this project was inspired by the publicly available repository https://github.com/i32-Sudo/PdFwKrnlMapper. However, this implementation has been significantly modified to load drivers directly from byte arrays in memory, rather than relying on file paths. This change enhances the stealth capabilities of the loader and avoids writing files to disk, which is often monitored by security software.

The loader demonstrates a series of sophisticated techniques:

1.  **Kernel Address Retrieval:** The program first identifies essential kernel addresses, including those of key security functions (`SeValidateImageHeader`, `SeValidateImageData`) and locations related to PatchGuard. This is accomplished using techniques such as reading from specific memory locations and scanning patterns of assembly instructions in `ntoskrnl.exe`.
2.  **Bypassing DSE (Driver Signature Enforcement):** It modifies the behavior of the `SeValidateImageHeader` and `SeValidateImageData` functions in kernel memory by rewriting their instructions to immediately return, effectively disabling the requirement for drivers to have a valid signature.
3.  **Bypassing PatchGuard:** It disables the PatchGuard using the information from the "PatchGuardOffset", by writing in the kernel memory, in order to ensure that the loaded driver is not detected by PatchGuard.
4.  **Loading a Vulnerable Driver (`pdfw_krnl`)**: It first loads an existing, signed but vulnerable driver using the function `NtLoadDriver`, which serves as a tool to communicate with the kernel memory. This driver provides an interface via `DeviceIoControl` that can read and write directly in memory.
5.  **Loading the Custom Driver**: It uses the `NtLoadDriver` function again to load a custom, unsigned kernel-mode driver using the same function as before, after having disabled DSE and PatchGuard.
6.  **Unloading the Vulnerable Driver**: It then proceeds to unload the vulnerable driver using `NtUnloadDriver`.

The code includes several key components:

*   **`Contourne.cpp` and `Contourne.h`**: The core logic of the application including the steps for bypassing DSE, PatchGuard, and orchestrating the driver loading process.
*   **`driver_data.cpp` and `driver_data.h`**: Contain the raw binary data of both the vulnerable and custom drivers, stored as byte arrays.
*   **`Hwd.cpp`**: A utility to get the serial number of the hard drive.
*  **`lazy.hpp`**: A custom lazy importer implementation that bypasses classic `LoadLibrary` and `GetProcAddress`.
*   **`Load.h/cpp`**: Provides the logic to load and unload kernel drivers using the `NtLoadDriver` and `NtUnloadDriver` native API.
*   **`main.cpp`**: The entry point of the user-mode application.
*   **`Scan.h/cpp`**: Memory scanning and pattern matching capabilities, that are used to fetch important addresses in memory.
*   **`Secure.h/cpp`**: Methods to read and write in the kernel memory using the vulnerable driver IOCTL interface.
*  **`skCrypt.h`:** A string cipher implementation to avoid having sensible data in the clear.
*   **`xor.h`:** A more secure string cipher implementation.
*  **`Utils.h/cpp`:** A series of functions to get kernel address and related offsets.

This repository is intended for research, educational purposes, and vulnerability analysis, and as such should be used responsibly and ethically. I am not responsible for the use you may have of it or for any ban in video games. Please note that this code makes low-level changes to a Windows system that can destabilize it, you must be extremly careful when using it. This project doesn't imply that this code can evade most anti-cheat or anti-virus solutions, and that the protection mechanisms are constantly evolving.

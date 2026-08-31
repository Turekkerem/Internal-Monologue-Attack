# Advanced Internal Monologue (C++ SSPI NTLM Extractor)

> *"Have you ever thought to yourself, is it possible to have the victim and the attacker with turned on Responder on one machine? I have, and I thought: wow, this would be very interesting if malware were using that technique..."*

## Overview

**Internal Monologue** is a security research concept demonstrating how local authentication mechanisms can be abused via the Windows Security Support Provider Interface (SSPI) to capture NetNTLMv2 hashes without dumping sensitive process memory (such as `lsass.exe`). 

This project is a standalone, single-file C++ implementation designed for educational and defensive auditing purposes. It simulates a local loopback authentication cycle, forcing the operating system to negotiate an NTLM handshake and return a fully compatible hash ready for offline cracking tools like **Hashcat**.

---

## Key Features

* **Single-File Architecture:** No complex Visual Studio project structures or external heavy dependencies required. Easily compilable using lightweight toolchains like MinGW-w64 (`g++`).
* **Native SSPI Integration:** Leverages official Windows APIs (`secur32.dll`) to interact directly with the NTLM Security Support Provider (SSP), ensuring proper cryptographic structures and target information (`TargetInfo` / `AV_Pairs`) without triggering manual token malformation errors.
* **TCP Loopback Handshake:** Implements a multi-threaded local server/client architecture (`127.0.0.1`) that cleanly executes the complete NTLM flow (`Type-1` $\rightarrow$ `Type-2` $\rightarrow$ `Type-3`).
* **Hashcat Compatibility:** Automatically parses the binary response structure of the `Type-3` authentication packet, stripping unnecessary GSSAPI/NTLMSSP headers and formatting the output strictly for **Hashcat (mode 5600)**.


---

## How It Works

1. **Server Initialization:** A secondary background thread starts a local TCP listener on `127.0.0.1` and acquires server-side NTLM credentials using `AcquireCredentialsHandleW`.
2. **Type-1 (Negotiate):** The client application initiates an outbound NTLM security context using `InitializeSecurityContextW`, generating the initial negotiate token.
3. **Type-2 (Challenge):** The local server receives the token and processes it via `AcceptSecurityContext`, forcing Windows to generate a cryptographic server challenge and valid target attributes.
4. **Type-3 (Authenticate):** The client processes the challenge and produces the final authentication token containing the encrypted NTLMv2 response.
5. **Hash Extraction:** The server intercepts the `Type-3` message, extracts the 8-byte challenge and the dynamic `NtChallengeResponse` blob, combines them with the current user and domain names, and outputs a ready-to-crack NetNTLMv2 hash string.
<img width="1082" height="528" alt="image" src="https://github.com/user-attachments/assets/697d5a41-c4f4-469a-ad9b-9cd3e4700e29" />

---

## Compilation

To compile the project cleanly without Visual Studio using **MinGW-w64**:

```bash
g++ -o ntlm_internal_monologue.exe ntlm_internal_monologue.cpp -lws2_32 -lsecur32 -lcrypt32 -pthread # Internal Monologue Attack
```
**Important Note: Known Issue – Hash Corruption Due to Offset Parsing**

The current implementation successfully completes the NTLM handshake (`Type-1` → `Type-2` → `Type-3`) and extracts a hash-like string. However, **the extracted hash is corrupted** and **not accepted by Hashcat** (mode 5600) or any other cracking tool.

The root cause has been traced to **incorrect offset calculations** when parsing the `Type-3` (Authenticate) message:

- The code reads the length and offset of the NT response from positions `+16` and `+20`, respectively.  
- According to the NTLMSSP specification, the correct offsets are **`+20`** (length) and **`+24`** (offset).  
- As a result, the extracted data corresponds to the **LM Response** or other header fields, not the actual `NtChallengeResponse` blob.

Attempts to correct this by manually detecting the `"NTLMSSP"` signature and adjusting the pointer do **not** resolve the issue – they only mask the symptom, leaving the underlying parsing error intact.

**No reliable fix has been identified at this time (I just don't know how to fix it)**  
The problem is structural and would require a complete rewrite of the `Type-3` parsing logic, including proper handling of the `AV_Pairs` structure and verification of the `NTLMv2` response format.

This version is provided **as-is for educational and research purposes only**.  
It serves as a demonstration of the SSPI authentication flow but **should not be relied upon for producing valid NetNTLMv2 hashes**.

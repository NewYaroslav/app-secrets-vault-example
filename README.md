# app-secrets-vault-example

A minimal C++11 secrets vault for applications.  
Demonstrates how to combine:

- **PBKDF2-HMAC-SHA256** (from [hmac-cpp])  
- **AES-256-GCM** (from [aes-cpp])  
- Optional **pepper** (device/OS-bound secret, via [pepper-cpp])  
- Optional **obfy** for basic code/data obfuscation  

The examples encrypt a simple payload (`email` + `password`) and store it in
different formats.

---

## Overview

This repository contains three standalone demo programs:

- **`simple.cpp`**  
  Minimal colon-separated format (`iters:salt:iv:tag:ct`).  
  Easy to follow for first steps.

- **`json_vault.cpp`**  
  Stores fields as a structured JSON object with Base64 values.  
  Allows explicit inspection of parameters (`v`, `kdf`, `aead`).

- **`jwr_vault.cpp`**  
  Compact "JWR" (JSON Web Record) token:  
  `base64url(header) . base64url(body)`  
  Inspired by JWT but with encrypted payload.

All examples implement the same flow:

1. Derive a 32-byte key with PBKDF2(passphrase, salt, pepper, iters).  
2. Encrypt `{"email","password"}` with AES-256-GCM.  
3. Serialize to chosen format and write to file.  
4. Read back, parse, re-derive key, decrypt, and return payload.

---

## Threat Model

- Secrets reside only on the device, so an attacker may have offline access.  
- There is no server-side component; all protection relies on local storage.  
- Obfuscation (`obfy`) only slows reverse engineering and **does not** replace
  cryptography.  
- Pepper is intended to bind key derivation to device/OS secrets.  
- These examples are **educational** and not a full password manager.

---

## Formats

### Simple format

```
<iters>:\<salt\_b64>:\<iv\_b64>:\<tag\_b64>:\<ct\_b64>
```

- `salt` = 16 bytes  
- `iv`   = 12 bytes (GCM standard)  
- `tag`  = 16 bytes  
- derived key length = 32 bytes  

### JSON vault

```json
{
  "v": 1,
  "kdf": {
    "alg": "pbkdf2-hmac-sha256",
    "iters": 300000,
    "salt": "BASE64...",
    "dkLen": 32
  },
  "aead": {
    "alg": "aes-256-gcm",
    "iv": "BASE64...",
    "tag": "BASE64..."
  },
  "ciphertext": "BASE64...",
  "aad": "BASE64..."   // optional
}
```

### JWR token

```
base64url(header).base64url(body)
```

* **Header (JSON, informational only):**

  ```json
  {"typ":"JWR","alg":"AES-256-GCM","kdf":"PBKDF2-HMAC-SHA256"}
  ```
* **Body:** JSON vault (same structure as above).

---

## Build

Requirements:

* C++11 compiler (tested with g++/clang++)
* \[aes-cpp], \[hmac-cpp], \[pepper-cpp], \[obfy] libraries

Using CMake:

```bash
git clone https://github.com/NewYaroslav/app-secrets-vault-example
cd app-secrets-vault-example
mkdir build && cd build
cmake ..
make
```

Or compile a single file directly (adjust include/lib paths):

```bash
g++ -std=c++11 simple.cpp -o simple -laes-cpp -lhmac-cpp -lobfy
```

---

## Usage

### Simple vault

```bash
./simple vault.bin user@example.com mypass
```

### JSON vault

```bash
./json_vault vault.json user@example.com mypass
```

Options:

* `--pepper=MODE` where MODE = `keystore` (default), `derived`, or `file`.
* `--deny-fallback` to disable fallback providers.

### JWR vault

```bash
./jwr_vault vault.jwr user@example.com mypass
```

Each program:

1. Writes an encrypted vault to `<path>`.
2. Reads it back.
3. Prints decrypted email/password (for demo only — do not print secrets in production).

---

## Pepper provider example

```cpp
pepper::Config cfg;
cfg.primary = pepper::StorageMode::OS_KEYCHAIN;
cfg.fallbacks = { pepper::StorageMode::MACHINE_BOUND,
                  pepper::StorageMode::ENCRYPTED_FILE };
cfg.key_id = OBFY_STR("com.example.secure-example/pepper:v1");
cfg.app_salt = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };

pepper::Provider prov(cfg);
std::vector<uint8_t> pepper32;
if (!prov.ensure(pepper32)) {
    /* handle error */
}
// pepper32 now holds a 32-byte pepper derived or stored via the configured backends.
```

---

## Pepper mode matrix

| `--pepper` value     | Uses OS key store | Default fallbacks             |
| -------------------- | ----------------- | ----------------------------- |
| `keystore` (default) | ✅                 | machine-bound, encrypted file |
| `derived`            | ❌                 | machine-bound, encrypted file |
| `file`               | ❌                 | machine-bound, encrypted file |

Use `--deny-fallback` to disable the fallback list and require only the selected primary store.

---

## References

* [hmac-cpp](https://github.com/NewYaroslav/hmac-cpp)
* [aes-cpp](https://github.com/NewYaroslav/aes-cpp)
* [pepper-cpp](https://github.com/NewYaroslav/pepper-cpp)
* [obfy](https://github.com/NewYaroslav/obfy)

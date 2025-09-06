# app-secrets-vault-example
A minimal C++11 secrets vault for apps using PBKDF2 (from hmac-cpp) and AES-GCM (from aes-cpp). Stores email/password in JSON with Base64 fields {ver,iters,salt,iv,ct,tag}; optional code obfuscation via obfy.

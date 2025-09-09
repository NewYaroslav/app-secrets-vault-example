# app-secrets-vault-example
A minimal C++11 secrets vault for apps using PBKDF2 (from hmac-cpp) and AES-GCM (from aes-cpp). Stores email/password in JSON with Base64 fields {ver,iters,salt,iv,ct,tag}; optional code obfuscation via obfy.

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

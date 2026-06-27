#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

class Crypto {
public:
    Crypto() = default;
    ~Crypto() = default;

    std::vector<uint8_t> DeriveKey(const std::string& password, const std::vector<uint8_t>& salt) const;
    std::vector<uint8_t> HashKey(const std::vector<uint8_t>& key) const;
    bool Encrypt(const std::string& plaintext, 
                 const std::vector<uint8_t>& key, 
                 std::vector<uint8_t>& out_ciphertext, 
                 std::vector<uint8_t>& out_iv, 
                 std::vector<uint8_t>& out_auth_tag) const;
    bool Decrypt(const std::vector<uint8_t>& ciphertext, 
                 const std::vector<uint8_t>& iv, 
                 const std::vector<uint8_t>& auth_tag, 
                 const std::vector<uint8_t>& key, 
                 std::string& out_plaintext) const;
    std::vector<uint8_t> GenerateRandomBytes(size_t size) const;
    std::string GeneratePassword(size_t length) const;
};
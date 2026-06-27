#include "../include/Crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <memory>

std::vector<uint8_t> Crypto::DeriveKey(const std::string& password, const std::vector<uint8_t>& salt) const {
    std::vector<uint8_t> key(32); // 256-bit key
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
                          salt.data(), static_cast<int>(salt.size()), 600000,
                          EVP_sha256(), static_cast<int>(key.size()), key.data()) != 1) {
        throw std::runtime_error("PBKDF2 key derivation failed.");
    }
    return key;
}

std::vector<uint8_t> Crypto::HashKey(const std::vector<uint8_t>& key) const {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    unsigned int length = 0;
    
    // RAII for OpenSSL Context
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) throw std::runtime_error("Failed to create hash context.");
    
    EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx.get(), key.data(), key.size());
    EVP_DigestFinal_ex(ctx.get(), hash.data(), &length);
    
    return hash;
}

bool Crypto::Encrypt(const std::string& plaintext, const std::vector<uint8_t>& key, 
                     std::vector<uint8_t>& out_ciphertext, std::vector<uint8_t>& out_iv, 
                     std::vector<uint8_t>& out_auth_tag) const {
    out_iv = GenerateRandomBytes(12); // 96-bit IV for GCM
    out_auth_tag.resize(16);
    out_ciphertext.resize(plaintext.length() + 16); // Buffer size

    // RAII for OpenSSL Context
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) return false;

    int len = 0, ciphertext_len = 0;
    bool success = false;

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(out_iv.size()), nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), out_iv.data()) == 1 &&
        EVP_EncryptUpdate(ctx.get(), out_ciphertext.data(), &len, 
                          reinterpret_cast<const uint8_t*>(plaintext.data()), static_cast<int>(plaintext.length())) == 1) {
        
        ciphertext_len = len;
        
        if (EVP_EncryptFinal_ex(ctx.get(), out_ciphertext.data() + len, &len) == 1) {
            ciphertext_len += len;
            out_ciphertext.resize(ciphertext_len);
            
            if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, out_auth_tag.data()) == 1) {
                success = true;
            }
        }
    }
    
    return success;
}

bool Crypto::Decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv, 
                     const std::vector<uint8_t>& auth_tag, const std::vector<uint8_t>& key, 
                     std::string& out_plaintext) const {
    
    // RAII for OpenSSL Context
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) return false;

    std::vector<uint8_t> plaintext_buffer(ciphertext.size());
    int len = 0, plaintext_len = 0;
    bool success = false;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) == 1 &&
        EVP_DecryptUpdate(ctx.get(), plaintext_buffer.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) == 1) {
        
        plaintext_len = len;
        
        // Cast away constness safely as OpenSSL API requires void* for this specific control operation
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(auth_tag.size()), 
                            const_cast<void*>(reinterpret_cast<const void*>(auth_tag.data())));

        if (EVP_DecryptFinal_ex(ctx.get(), plaintext_buffer.data() + len, &len) > 0) {
            plaintext_len += len;
            out_plaintext.assign(plaintext_buffer.begin(), plaintext_buffer.begin() + plaintext_len);
            success = true;
        }
    }

    return success;
}

std::vector<uint8_t> Crypto::GenerateRandomBytes(size_t size) const {
    std::vector<uint8_t> buffer(size);
    if (RAND_bytes(buffer.data(), static_cast<int>(size)) != 1) {
        throw std::runtime_error("Failed to generate random bytes.");
    }
    return buffer;
}

std::string Crypto::GeneratePassword(size_t length) const {
    const std::string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";
    std::string password;
    password.reserve(length);
    
    std::vector<uint8_t> rand_bytes = GenerateRandomBytes(length);
    for (size_t i = 0; i < length; ++i) {
        password += charset[rand_bytes[i] % charset.length()];
    }
    return password;
}
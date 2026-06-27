#include "../include/PasswordManager.h"
#include <openssl/crypto.h>
#include <algorithm>

PasswordManager::~PasswordManager() {
    LockVault();
}

bool PasswordManager::Initialize(const std::string& dbPath) {
    return db.Open(dbPath) && db.InitializeSchema();
}

bool PasswordManager::IsVaultConfigured() const {
    return db.IsConfigured();
}

bool PasswordManager::SetupVault(const std::string& masterPassword) {
    if (IsVaultConfigured()) return false;

    std::vector<uint8_t> salt = crypto.GenerateRandomBytes(16);
    std::vector<uint8_t> derivedKey = crypto.DeriveKey(masterPassword, salt);
    std::vector<uint8_t> masterHash = crypto.HashKey(derivedKey);

    if (db.SetConfig(masterHash, salt)) {
        activeKey = derivedKey;
        isUnlocked = true;
        return true;
    }

    OPENSSL_cleanse(derivedKey.data(), derivedKey.size());
    return false;
}

bool PasswordManager::UnlockVault(const std::string& masterPassword) {
    if (isUnlocked) return true;

    std::vector<uint8_t> storedHash;
    std::vector<uint8_t> salt;
    if (!db.GetConfig(storedHash, salt)) return false;

    std::vector<uint8_t> derivedKey = crypto.DeriveKey(masterPassword, salt);
    std::vector<uint8_t> testHash = crypto.HashKey(derivedKey);

    // Constant-time comparison to prevent timing attacks
    if (storedHash.size() == testHash.size() && 
        CRYPTO_memcmp(storedHash.data(), testHash.data(), storedHash.size()) == 0) {
        activeKey = derivedKey;
        isUnlocked = true;
        return true;
    }

    OPENSSL_cleanse(derivedKey.data(), derivedKey.size());
    return false;
}

void PasswordManager::LockVault() {
    if (!activeKey.empty()) {
        OPENSSL_cleanse(activeKey.data(), activeKey.size());
        activeKey.clear();
    }
    isUnlocked = false;
}

bool PasswordManager::IsUnlocked() const {
    return isUnlocked;
}

bool PasswordManager::AddEntry(const std::string& service, const std::string& account, const std::string& password) {
    if (!isUnlocked) return false;

    std::vector<uint8_t> ciphertext, iv, auth_tag;
    if (crypto.Encrypt(password, activeKey, ciphertext, iv, auth_tag)) {
        return db.CreateCredential(service, account, ciphertext, iv, auth_tag);
    }
    return false;
}

std::vector<DecryptedRecord> PasswordManager::GetAllEntries() const {
    std::vector<DecryptedRecord> results;
    if (!isUnlocked) return results;

    auto encryptedRecords = db.ReadAllCredentials();
    for (const auto& enc : encryptedRecords) {
        std::string plaintext;
        if (crypto.Decrypt(enc.ciphertext, enc.iv, enc.auth_tag, activeKey, plaintext)) {
            results.push_back({enc.id, enc.service_name, enc.account_name, plaintext});
        }
    }
    return results;
}

std::vector<DecryptedRecord> PasswordManager::SearchEntries(const std::string& query) const {
    std::vector<DecryptedRecord> results;
    if (!isUnlocked) return results;

    auto encryptedRecords = db.SearchCredentials(query);
    for (const auto& enc : encryptedRecords) {
        std::string plaintext;
        if (crypto.Decrypt(enc.ciphertext, enc.iv, enc.auth_tag, activeKey, plaintext)) {
            results.push_back({enc.id, enc.service_name, enc.account_name, plaintext});
        }
    }
    return results;
}

bool PasswordManager::UpdateEntry(int id, const std::string& service, const std::string& account, const std::string& newPassword) {
    if (!isUnlocked) return false;

    std::vector<uint8_t> ciphertext, iv, auth_tag;
    if (crypto.Encrypt(newPassword, activeKey, ciphertext, iv, auth_tag)) {
        return db.UpdateCredential(id, service, account, ciphertext, iv, auth_tag);
    }
    return false;
}

bool PasswordManager::DeleteEntry(int id) {
    if (!isUnlocked) return false;
    return db.DeleteCredential(id);
}

std::string PasswordManager::GenerateSecurePassword(size_t length) const {
    return crypto.GeneratePassword(length);
}
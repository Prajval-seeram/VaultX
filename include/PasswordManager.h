#pragma once

#include "Crypto.h"
#include "Database.h"
#include <string>
#include <vector>
#include <cstdint>

struct DecryptedRecord {
    int id;
    std::string service_name;
    std::string account_name;
    std::string plaintext_password;
};

class PasswordManager {
public:
    PasswordManager() = default;
    ~PasswordManager();

    bool Initialize(const std::string& dbPath);
    
    bool IsVaultConfigured() const;
    bool SetupVault(const std::string& masterPassword);
    bool UnlockVault(const std::string& masterPassword);
    void LockVault();
    bool IsUnlocked() const;
    
    bool AddEntry(const std::string& service, const std::string& account, const std::string& password);
    std::vector<DecryptedRecord> GetAllEntries() const;
    std::vector<DecryptedRecord> SearchEntries(const std::string& query) const;
    bool UpdateEntry(int id, const std::string& service, const std::string& account, const std::string& newPassword);
    bool DeleteEntry(int id);
    
    std::string GenerateSecurePassword(size_t length) const;

private:
    Crypto crypto;
    Database db;
    bool isUnlocked = false;
    std::vector<uint8_t> activeKey;
};
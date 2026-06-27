#pragma once

#include <string>
#include <vector>
#include <cstdint>

struct EncryptedRecord {
    int id;
    std::string service_name;
    std::string account_name;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> auth_tag;
};

// Forward declaration of sqlite3 to avoid including the header here
struct sqlite3;

class Database {
public:
    Database() = default;
    ~Database();

    bool Open(const std::string& dbPath);
    void Close();
    bool InitializeSchema();
    
    bool IsConfigured() const;
    bool SetConfig(const std::vector<uint8_t>& masterHash, const std::vector<uint8_t>& salt);
    bool GetConfig(std::vector<uint8_t>& out_masterHash, std::vector<uint8_t>& out_salt) const;
    
    bool CreateCredential(const std::string& service, const std::string& account, 
                          const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv, 
                          const std::vector<uint8_t>& authTag);
    std::vector<EncryptedRecord> ReadAllCredentials() const;
    std::vector<EncryptedRecord> SearchCredentials(const std::string& query) const;
    bool UpdateCredential(int id, const std::string& service, const std::string& account, 
                          const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv, 
                          const std::vector<uint8_t>& authTag);
    bool DeleteCredential(int id);

private:
    sqlite3* db = nullptr;
};
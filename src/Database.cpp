#include "../include/Database.h"
#include <sqlite3.h>
#include <stdexcept>
#include <memory>

Database::~Database() {
    Close();
}

bool Database::Open(const std::string& dbPath) {
    return sqlite3_open(dbPath.c_str(), &db) == SQLITE_OK;
}

void Database::Close() {
    if (db) {
        sqlite3_close(db);
        db = nullptr;
    }
}

bool Database::InitializeSchema() {
    if (!db) return false;
    
    const char* config_sql = "CREATE TABLE IF NOT EXISTS vault_config ("
                             "master_hash BLOB NOT NULL, "
                             "salt BLOB NOT NULL);";
                             
    const char* cred_sql = "CREATE TABLE IF NOT EXISTS credentials ("
                           "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                           "service_name TEXT NOT NULL, "
                           "account_name TEXT NOT NULL, "
                           "ciphertext BLOB NOT NULL, "
                           "iv BLOB NOT NULL, "
                           "auth_tag BLOB NOT NULL);";

    char* errMsg = nullptr;
    if (sqlite3_exec(db, config_sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        sqlite3_free(errMsg);
        return false;
    }
    if (sqlite3_exec(db, cred_sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

bool Database::IsConfigured() const {
    if (!db) return false;
    
    const char* sql = "SELECT COUNT(*) FROM vault_config;";
    sqlite3_stmt* raw_stmt = nullptr;
    bool isConfigured = false;
    
    if (sqlite3_prepare_v2(db, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt(raw_stmt, sqlite3_finalize);
        if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            isConfigured = (sqlite3_column_int(stmt.get(), 0) > 0);
        }
    }
    return isConfigured;
}

bool Database::SetConfig(const std::vector<uint8_t>& masterHash, const std::vector<uint8_t>& salt) {
    if (!db) return false;

    const char* sql = "INSERT INTO vault_config (master_hash, salt) VALUES (?, ?);";
    sqlite3_stmt* raw_stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) return false;
    
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt(raw_stmt, sqlite3_finalize);
    sqlite3_bind_blob(stmt.get(), 1, masterHash.data(), static_cast<int>(masterHash.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt.get(), 2, salt.data(), static_cast<int>(salt.size()), SQLITE_TRANSIENT);
    
    return (sqlite3_step(stmt.get()) == SQLITE_DONE);
}

bool Database::GetConfig(std::vector<uint8_t>& out_masterHash, std::vector<uint8_t>& out_salt) const {
    if (!db) return false;

    const char* sql = "SELECT master_hash, salt FROM vault_config LIMIT 1;";
    sqlite3_stmt* raw_stmt = nullptr;
    bool success = false;
    
    if (sqlite3_prepare_v2(db, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt(raw_stmt, sqlite3_finalize);
        if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            const void* hashBlob = sqlite3_column_blob(stmt.get(), 0);
            int hashSize = sqlite3_column_bytes(stmt.get(), 0);
            out_masterHash.assign(static_cast<const uint8_t*>(hashBlob), static_cast<const uint8_t*>(hashBlob) + hashSize);
            
            const void* saltBlob = sqlite3_column_blob(stmt.get(), 1);
            int saltSize = sqlite3_column_bytes(stmt.get(), 1);
            out_salt.assign(static_cast<const uint8_t*>(saltBlob), static_cast<const uint8_t*>(saltBlob) + saltSize);
            
            success = true;
        }
    }
    return success;
}

bool Database::CreateCredential(const std::string& service, const std::string& account, 
                                const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv, 
                                const std::vector<uint8_t>& authTag) {
    if (!db) return false;

    const char* sql = "INSERT INTO credentials (service_name, account_name, ciphertext, iv, auth_tag) VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt* raw_stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) return false;
    
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt(raw_stmt, sqlite3_finalize);
    sqlite3_bind_text(stmt.get(), 1, service.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, account.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt.get(), 3, ciphertext.data(), static_cast<int>(ciphertext.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt.get(), 4, iv.data(), static_cast<int>(iv.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt.get(), 5, authTag.data(), static_cast<int>(authTag.size()), SQLITE_TRANSIENT);
    
    return (sqlite3_step(stmt.get()) == SQLITE_DONE);
}

std::vector<EncryptedRecord> Database::ReadAllCredentials() const {
    std::vector<EncryptedRecord> records;
    if (!db) return records;

    const char* sql = "SELECT id, service_name, account_name, ciphertext, iv, auth_tag FROM credentials;";
    sqlite3_stmt* raw_stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt(raw_stmt, sqlite3_finalize);
        while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            EncryptedRecord rec;
            rec.id = sqlite3_column_int(stmt.get(), 0);
            rec.service_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
            rec.account_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
            
            auto getBlob = [](sqlite3_stmt* s, int col) {
                const void* blob = sqlite3_column_blob(s, col);
                int size = sqlite3_column_bytes(s, col);
                return std::vector<uint8_t>(static_cast<const uint8_t*>(blob), static_cast<const uint8_t*>(blob) + size);
            };
            
            rec.ciphertext = getBlob(stmt.get(), 3);
            rec.iv = getBlob(stmt.get(), 4);
            rec.auth_tag = getBlob(stmt.get(), 5);
            
            records.push_back(std::move(rec));
        }
    }
    return records;
}

std::vector<EncryptedRecord> Database::SearchCredentials(const std::string& query) const {
    std::vector<EncryptedRecord> records;
    if (!db) return records;

    const char* sql = "SELECT id, service_name, account_name, ciphertext, iv, auth_tag FROM credentials WHERE service_name LIKE ? OR account_name LIKE ?;";
    sqlite3_stmt* raw_stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt(raw_stmt, sqlite3_finalize);
        std::string wildcardQuery = "%" + query + "%";
        sqlite3_bind_text(stmt.get(), 1, wildcardQuery.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 2, wildcardQuery.c_str(), -1, SQLITE_TRANSIENT);

        while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            EncryptedRecord rec;
            rec.id = sqlite3_column_int(stmt.get(), 0);
            rec.service_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
            rec.account_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
            
            auto getBlob = [](sqlite3_stmt* s, int col) {
                const void* blob = sqlite3_column_blob(s, col);
                int size = sqlite3_column_bytes(s, col);
                return std::vector<uint8_t>(static_cast<const uint8_t*>(blob), static_cast<const uint8_t*>(blob) + size);
            };
            
            rec.ciphertext = getBlob(stmt.get(), 3);
            rec.iv = getBlob(stmt.get(), 4);
            rec.auth_tag = getBlob(stmt.get(), 5);
            
            records.push_back(std::move(rec));
        }
    }
    return records;
}

bool Database::UpdateCredential(int id, const std::string& service, const std::string& account, 
                                const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv, 
                                const std::vector<uint8_t>& authTag) {
    if (!db) return false;

    const char* sql = "UPDATE credentials SET service_name = ?, account_name = ?, ciphertext = ?, iv = ?, auth_tag = ? WHERE id = ?;";
    sqlite3_stmt* raw_stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) return false;
    
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt(raw_stmt, sqlite3_finalize);
    sqlite3_bind_text(stmt.get(), 1, service.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, account.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt.get(), 3, ciphertext.data(), static_cast<int>(ciphertext.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt.get(), 4, iv.data(), static_cast<int>(iv.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt.get(), 5, authTag.data(), static_cast<int>(authTag.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.get(), 6, id);
    
    return (sqlite3_step(stmt.get()) == SQLITE_DONE);
}

bool Database::DeleteCredential(int id) {
    if (!db) return false;

    const char* sql = "DELETE FROM credentials WHERE id = ?;";
    sqlite3_stmt* raw_stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) return false;
    
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt(raw_stmt, sqlite3_finalize);
    sqlite3_bind_int(stmt.get(), 1, id);
    
    return (sqlite3_step(stmt.get()) == SQLITE_DONE);
}
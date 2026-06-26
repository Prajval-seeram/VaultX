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

bool Database::IsConfigured() {
    if (!db) return false;
    
    const char* sql = "SELECT COUNT(*) FROM vault_config;";
    sqlite3_stmt* stmt = nullptr;
    bool isConfigured = false;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            isConfigured = (sqlite3_column_int(stmt, 0) > 0);
        }
    }
    sqlite3_finalize(stmt);
    return isConfigured;
}

bool Database::SetConfig(const std::vector<uint8_t>& masterHash, const std::vector<uint8_t>& salt) {
    if (!db) return false;

    const char* sql = "INSERT INTO vault_config (master_hash, salt) VALUES (?, ?);";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    
    sqlite3_bind_blob(stmt, 1, masterHash.data(), static_cast<int>(masterHash.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, salt.data(), static_cast<int>(salt.size()), SQLITE_TRANSIENT);
    
    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return success;
}

bool Database::GetConfig(std::vector<uint8_t>& out_masterHash, std::vector<uint8_t>& out_salt) {
    if (!db) return false;

    const char* sql = "SELECT master_hash, salt FROM vault_config LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    bool success = false;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* hashBlob = sqlite3_column_blob(stmt, 0);
            int hashSize = sqlite3_column_bytes(stmt, 0);
            out_masterHash.assign(static_cast<const uint8_t*>(hashBlob), static_cast<const uint8_t*>(hashBlob) + hashSize);
            
            const void* saltBlob = sqlite3_column_blob(stmt, 1);
            int saltSize = sqlite3_column_bytes(stmt, 1);
            out_salt.assign(static_cast<const uint8_t*>(saltBlob), static_cast<const uint8_t*>(saltBlob) + saltSize);
            
            success = true;
        }
    }
    sqlite3_finalize(stmt);
    return success;
}

bool Database::CreateCredential(const std::string& service, const std::string& account, 
                                const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv, 
                                const std::vector<uint8_t>& authTag) {
    if (!db) return false;

    const char* sql = "INSERT INTO credentials (service_name, account_name, ciphertext, iv, auth_tag) VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    
    sqlite3_bind_text(stmt, 1, service.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, account.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, ciphertext.data(), static_cast<int>(ciphertext.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 4, iv.data(), static_cast<int>(iv.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 5, authTag.data(), static_cast<int>(authTag.size()), SQLITE_TRANSIENT);
    
    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return success;
}

std::vector<EncryptedRecord> Database::ReadAllCredentials() {
    std::vector<EncryptedRecord> records;
    if (!db) return records;

    const char* sql = "SELECT id, service_name, account_name, ciphertext, iv, auth_tag FROM credentials;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            EncryptedRecord rec;
            rec.id = sqlite3_column_int(stmt, 0);
            rec.service_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            rec.account_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            
            auto getBlob = [](sqlite3_stmt* s, int col) {
                const void* blob = sqlite3_column_blob(s, col);
                int size = sqlite3_column_bytes(s, col);
                return std::vector<uint8_t>(static_cast<const uint8_t*>(blob), static_cast<const uint8_t*>(blob) + size);
            };
            
            rec.ciphertext = getBlob(stmt, 3);
            rec.iv = getBlob(stmt, 4);
            rec.auth_tag = getBlob(stmt, 5);
            
            records.push_back(std::move(rec));
        }
    }
    sqlite3_finalize(stmt);
    return records;
}

std::vector<EncryptedRecord> Database::SearchCredentials(const std::string& query) {
    std::vector<EncryptedRecord> records;
    if (!db) return records;

    const char* sql = "SELECT id, service_name, account_name, ciphertext, iv, auth_tag FROM credentials WHERE service_name LIKE ? OR account_name LIKE ?;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        std::string wildcardQuery = "%" + query + "%";
        sqlite3_bind_text(stmt, 1, wildcardQuery.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, wildcardQuery.c_str(), -1, SQLITE_TRANSIENT);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            EncryptedRecord rec;
            rec.id = sqlite3_column_int(stmt, 0);
            rec.service_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            rec.account_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            
            auto getBlob = [](sqlite3_stmt* s, int col) {
                const void* blob = sqlite3_column_blob(s, col);
                int size = sqlite3_column_bytes(s, col);
                return std::vector<uint8_t>(static_cast<const uint8_t*>(blob), static_cast<const uint8_t*>(blob) + size);
            };
            
            rec.ciphertext = getBlob(stmt, 3);
            rec.iv = getBlob(stmt, 4);
            rec.auth_tag = getBlob(stmt, 5);
            
            records.push_back(std::move(rec));
        }
    }
    sqlite3_finalize(stmt);
    return records;
}

bool Database::UpdateCredential(int id, const std::string& service, const std::string& account, 
                                const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv, 
                                const std::vector<uint8_t>& authTag) {
    if (!db) return false;

    const char* sql = "UPDATE credentials SET service_name = ?, account_name = ?, ciphertext = ?, iv = ?, auth_tag = ? WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    
    sqlite3_bind_text(stmt, 1, service.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, account.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, ciphertext.data(), static_cast<int>(ciphertext.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 4, iv.data(), static_cast<int>(iv.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 5, authTag.data(), static_cast<int>(authTag.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, id);
    
    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return success;
}

bool Database::DeleteCredential(int id) {
    if (!db) return false;

    const char* sql = "DELETE FROM credentials WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    
    sqlite3_bind_int(stmt, 1, id);
    
    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return success;
}
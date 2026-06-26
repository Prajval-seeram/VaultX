#include "../include/PasswordManager.h"
#include <iostream>
#include <string>
#include <limits>
#include <iomanip>

namespace {
    void ClearScreen() {
        // ANSI escape code to clear screen
        std::cout << "\033[2J\033[1;1H";
    }

    void FlushInput() {
        if (std::cin.fail()) {
            std::cin.clear();
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    std::string ReadString(const std::string& prompt) {
        std::string input;
        std::cout << prompt;
        std::getline(std::cin, input);
        return input;
    }

    int ReadInt(const std::string& prompt) {
        int value;
        while (true) {
            std::cout << prompt;
            if (std::cin >> value) {
                FlushInput();
                return value;
            }
            std::cout << "Invalid input. Please enter a valid number.\n";
            FlushInput();
        }
    }

    void DisplayHeader(const std::string& title) {
        ClearScreen();
        std::cout << "====================================\n";
        std::cout << "          " << title << "\n";
        std::cout << "====================================\n";
    }
}

int main() {
    PasswordManager pm;
    
    // Note: Ensure the "database" directory exists relative to execution path, 
    // or SQLite will fail to create the file.
    if (!pm.Initialize("vault.db")) {
        std::cerr << "Fatal Error: Could not initialize database.\n";
        return 1;
    }

    bool running = true;

    while (running) {
        if (!pm.IsVaultConfigured()) {
            DisplayHeader("VAULTX: SETUP (FIRST RUN)");
            std::cout << "1. Setup Master Password\n";
            std::cout << "2. Exit\n";
            
            int choice = ReadInt("\nSelect an option: ");
            
            if (choice == 1) {
                std::string pass1 = ReadString("Enter new Master Password: ");
                std::string pass2 = ReadString("Confirm Master Password: ");
                
                if (pass1 != pass2 || pass1.empty()) {
                    std::cout << "\nPasswords do not match or are empty. Press Enter to retry.\n";
                    std::cin.get();
                } else if (pm.SetupVault(pass1)) {
                    std::cout << "\nVault configured successfully! Press Enter to continue.\n";
                    std::cin.get();
                } else {
                    std::cout << "\nFailed to configure vault. Press Enter to exit.\n";
                    std::cin.get();
                    return 1;
                }
            } else if (choice == 2) {
                running = false;
            }
        } 
        else if (!pm.IsUnlocked()) {
            DisplayHeader("VAULTX: MAIN MENU (LOCKED)");
            std::cout << "1. Unlock Vault\n";
            std::cout << "2. Exit\n";
            
            int choice = ReadInt("\nSelect an option: ");
            
            if (choice == 1) {
                std::string pass = ReadString("Enter Master Password: ");
                if (pm.UnlockVault(pass)) {
                    std::cout << "\nVault unlocked successfully! Press Enter to enter workspace.\n";
                    std::cin.get();
                } else {
                    std::cout << "\nIncorrect Master Password. Press Enter to retry.\n";
                    std::cin.get();
                }
            } else if (choice == 2) {
                running = false;
            }
        } 
        else {
            DisplayHeader("VAULTX: WORKSPACE (UNLOCKED)");
            std::cout << "1. Add New Credential\n";
            std::cout << "2. View All Credentials\n";
            std::cout << "3. Search Credentials\n";
            std::cout << "4. Update Existing Credential\n";
            std::cout << "5. Delete Credential\n";
            std::cout << "6. Generate Strong Password\n";
            std::cout << "7. Lock Vault\n";
            std::cout << "8. Exit\n";
            
            int choice = ReadInt("\nSelect an option: ");
            
            switch (choice) {
                case 1: {
                    DisplayHeader("ADD CREDENTIAL");
                    std::string service = ReadString("Service Name: ");
                    std::string account = ReadString("Account/Username: ");
                    std::string password = ReadString("Password: ");
                    
                    if (pm.AddEntry(service, account, password)) {
                        std::cout << "\nCredential saved successfully.\n";
                    } else {
                        std::cout << "\nFailed to save credential.\n";
                    }
                    std::cout << "Press Enter to return.";
                    std::cin.get();
                    break;
                }
                case 2: {
                    DisplayHeader("ALL CREDENTIALS");
                    auto entries = pm.GetAllEntries();
                    if (entries.empty()) {
                        std::cout << "No credentials found in the vault.\n";
                    } else {
                        for (const auto& entry : entries) {
                            std::cout << "[" << entry.id << "] " 
                                      << entry.service_name << " | " 
                                      << entry.account_name << " | " 
                                      << entry.plaintext_password << "\n";
                        }
                    }
                    std::cout << "\nPress Enter to return.";
                    std::cin.get();
                    break;
                }
                case 3: {
                    DisplayHeader("SEARCH CREDENTIALS");
                    std::string query = ReadString("Search for Service or Account: ");
                    auto entries = pm.SearchEntries(query);
                    if (entries.empty()) {
                        std::cout << "\nNo matching credentials found.\n";
                    } else {
                        std::cout << "\nSearch Results:\n";
                        for (const auto& entry : entries) {
                            std::cout << "[" << entry.id << "] " 
                                      << entry.service_name << " | " 
                                      << entry.account_name << " | " 
                                      << entry.plaintext_password << "\n";
                        }
                    }
                    std::cout << "\nPress Enter to return.";
                    std::cin.get();
                    break;
                }
                case 4: {
                    DisplayHeader("UPDATE CREDENTIAL");
                    int id = ReadInt("Enter Credential ID to update: ");
                    std::string service = ReadString("New Service Name: ");
                    std::string account = ReadString("New Account/Username: ");
                    std::string password = ReadString("New Password: ");
                    
                    if (pm.UpdateEntry(id, service, account, password)) {
                        std::cout << "\nCredential updated successfully.\n";
                    } else {
                        std::cout << "\nFailed to update credential. Check if ID exists.\n";
                    }
                    std::cout << "Press Enter to return.";
                    std::cin.get();
                    break;
                }
                case 5: {
                    DisplayHeader("DELETE CREDENTIAL");
                    int id = ReadInt("Enter Credential ID to delete: ");
                    if (pm.DeleteEntry(id)) {
                        std::cout << "\nCredential deleted successfully.\n";
                    } else {
                        std::cout << "\nFailed to delete credential.\n";
                    }
                    std::cout << "Press Enter to return.";
                    std::cin.get();
                    break;
                }
                case 6: {
                    DisplayHeader("PASSWORD GENERATOR");
                    int length = ReadInt("Enter desired password length (e.g., 16): ");
                    if (length > 0 && length <= 128) {
                        std::string generated = pm.GenerateSecurePassword(length);
                        std::cout << "\nGenerated Password: " << generated << "\n";
                    } else {
                        std::cout << "\nInvalid length. Please choose between 1 and 128.\n";
                    }
                    std::cout << "\nPress Enter to return.";
                    std::cin.get();
                    break;
                }
                case 7: {
                    pm.LockVault();
                    std::cout << "\nVault locked. Press Enter to continue.\n";
                    std::cin.get();
                    break;
                }
                case 8: {
                    pm.LockVault();
                    running = false;
                    break;
                }
                default: {
                    std::cout << "\nInvalid option. Press Enter to try again.\n";
                    std::cin.get();
                    break;
                }
            }
        }
    }

    return 0;
}
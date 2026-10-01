/**
 * @file test_vault_integration.cpp
 * @brief End-to-end integration and round-trip tests for VaultManager in kvault.
 */

#include "VaultManager.hpp"
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>

using namespace kvault;

class VaultIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_vaultDir = std::filesystem::temp_directory_path() / "kvault_test_vault";
        m_scratchDir = std::filesystem::temp_directory_path() / "kvault_test_scratch";

        std::filesystem::remove_all(m_vaultDir);
        std::filesystem::remove_all(m_scratchDir);

        std::filesystem::create_directories(m_scratchDir);
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(m_vaultDir, ec);
        std::filesystem::remove_all(m_scratchDir, ec);
    }

    std::filesystem::path createDummyFile(const std::string& name, size_t sizeBytes) {
        auto p = m_scratchDir / name;
        std::ofstream ofs(p, std::ios::binary);
        std::vector<uint8_t> buffer(sizeBytes);
        for (size_t i = 0; i < sizeBytes; ++i) {
            buffer[i] = static_cast<uint8_t>((i * 7 + 13) & 0xFF);
        }
        ofs.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        return p;
    }

    std::filesystem::path m_vaultDir;
    std::filesystem::path m_scratchDir;
};

TEST_F(VaultIntegrationTest, VaultInitializationLifecycle) {
    VaultManager vault(m_vaultDir);
    EXPECT_TRUE(vault.initializeVault());

    // Second initialization should fail (idempotency guard)
    EXPECT_FALSE(vault.initializeVault());

    auto status = vault.inspectStatus();
    EXPECT_TRUE(status.is_initialized);
    EXPECT_EQ(status.file_count, 0);
}

TEST_F(VaultIntegrationTest, EncryptDecryptRoundTripSmallFile) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    std::string testFilename = "confidential.txt";
    auto sourcePath = createDummyFile(testFilename, 1024); // 1 KiB
    std::string passphrase = "CorrectHorseBatteryStaple2026!";

    // Encrypt
    ASSERT_TRUE(vault.encryptFile(sourcePath, passphrase));

    auto status = vault.inspectStatus();
    EXPECT_EQ(status.file_count, 1);
    EXPECT_GT(status.total_vault_bytes, 1024);

    // Decrypt
    auto restoredPath = m_scratchDir / "restored.txt";
    ASSERT_TRUE(vault.decryptFile(testFilename, restoredPath, passphrase));

    // Verify bit-for-bit equality
    EXPECT_EQ(std::filesystem::file_size(sourcePath), std::filesystem::file_size(restoredPath));

    std::ifstream orig(sourcePath, std::ios::binary);
    std::ifstream rest(restoredPath, std::ios::binary);

    std::vector<uint8_t> origData((std::istreambuf_iterator<char>(orig)), {});
    std::vector<uint8_t> restData((std::istreambuf_iterator<char>(rest)), {});

    EXPECT_EQ(origData, restData);
}

TEST_F(VaultIntegrationTest, EncryptDecryptMultiChunkLargeFile) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    // 150 KiB spans across 3 * 64 KiB chunks, validating streaming & PKCS#7 padding
    std::string testFilename = "large_payload.bin";
    auto sourcePath = createDummyFile(testFilename, 150 * 1024);
    std::string passphrase = "MultiChunkStreamingPassphrase#1";

    ASSERT_TRUE(vault.encryptFile(sourcePath, passphrase));

    auto restoredPath = m_scratchDir / "large_restored.bin";
    ASSERT_TRUE(vault.decryptFile(testFilename, restoredPath, passphrase));

    EXPECT_EQ(std::filesystem::file_size(sourcePath), std::filesystem::file_size(restoredPath));

    std::ifstream orig(sourcePath, std::ios::binary);
    std::ifstream rest(restoredPath, std::ios::binary);

    std::vector<uint8_t> origData((std::istreambuf_iterator<char>(orig)), {});
    std::vector<uint8_t> restData((std::istreambuf_iterator<char>(rest)), {});

    EXPECT_EQ(origData, restData);
}

TEST_F(VaultIntegrationTest, RejectIncorrectPassphrase) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    std::string testFilename = "secret.doc";
    auto sourcePath = createDummyFile(testFilename, 512);
    std::string realPass = "RealPassphrase123";
    std::string wrongPass = "WrongPassphrase999";

    ASSERT_TRUE(vault.encryptFile(sourcePath, realPass));

    auto restoredPath = m_scratchDir / "never_created.doc";
    EXPECT_FALSE(vault.decryptFile(testFilename, restoredPath, wrongPass));
    EXPECT_FALSE(std::filesystem::exists(restoredPath));
}

TEST_F(VaultIntegrationTest, RejectTamperedCiphertext) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    std::string testFilename = "unaltered.bin";
    auto sourcePath = createDummyFile(testFilename, 256);
    std::string pass = "SecureMasterPassword#1";

    ASSERT_TRUE(vault.encryptFile(sourcePath, pass));

    // Tamper with record file in vault
    auto recordPath = m_vaultDir / "records" / (testFilename + ".enc");
    ASSERT_TRUE(std::filesystem::exists(recordPath));

    {
        std::fstream stream(recordPath, std::ios::in | std::ios::out | std::ios::binary);
        // Tamper with a payload byte past the 96-byte header
        stream.seekp(105);
        char b = 0;
        stream.read(&b, 1);
        b ^= 0xFF; // Flip all bits
        stream.seekp(105);
        stream.write(&b, 1);
    }

    auto restoredPath = m_scratchDir / "tampered_restored.bin";
    EXPECT_FALSE(vault.decryptFile(testFilename, restoredPath, pass));
    EXPECT_FALSE(std::filesystem::exists(restoredPath));
}

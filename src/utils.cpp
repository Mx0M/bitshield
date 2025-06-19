#include "utils.h"
#include <openssl/sha.h>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <vector>
#include <iostream>
#include "aes.h"
#include <openssl/evp.h>

std::string sha256_file(const std::string &path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return "";
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return "";

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    char buf[4096];
    while (file.read(buf, sizeof(buf)))
    {
        if (EVP_DigestUpdate(ctx, buf, file.gcount()) != 1)
        {
            EVP_MD_CTX_free(ctx);
            return "";
        }
    }
    // Read remaining bytes (if any)
    if (file.gcount() > 0)
    {
        if (EVP_DigestUpdate(ctx, buf, file.gcount()) != 1)
        {
            EVP_MD_CTX_free(ctx);
            return "";
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);

    std::ostringstream result;
    for (unsigned int i = 0; i < hash_len; ++i)
    {
        result << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return result.str();
    // SHA256_CTX ctx;
    // SHA256_Init(&ctx);

    // char buf[4096];
    // while (file.read(buf, sizeof(buf)))
    // {
    //     SHA256_Update(&ctx, buf, file.gcount());
    // }
    // // Also handle any remaining bytes
    // if (file.gcount() > 0)
    // {
    //     SHA256_Update(&ctx, buf, file.gcount());
    // }

    // unsigned char hash[SHA256_DIGEST_LENGTH];
    // SHA256_Final(hash, &ctx);

    // std::ostringstream result;
    // for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    //     result << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];

    // return result.str();
}

std::vector<uint8_t> read_file_binary(const std::string &path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return {};
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
}

std::string get_filename(const std::string &path)
{
    return std::filesystem::path(path).filename().string();
}

double calculate_entropy(const std::vector<uint8_t> &data)
{
    if (data.empty())
        return 0.0;

    std::vector<int> freq(256, 0);
    for (uint8_t byte : data)
        freq[byte]++;

    double entropy = 0.0;
    for (int count : freq)
    {
        if (count == 0)
            continue;
        double p = static_cast<double>(count) / data.size();
        entropy -= p * std::log2(p);
    }

    return entropy;
}

std::vector<std::string> collect_files(const std::string &path)
{
    std::vector<std::string> files;
    namespace fs = std::filesystem;

    if (fs::is_regular_file(path))
    {
        files.push_back(path);
    }
    else if (fs::is_directory(path))
    {
        for (const auto &entry : fs::recursive_directory_iterator(path))
        {
            if (fs::is_regular_file(entry.path()))
            {
                files.push_back(entry.path().string());
            }
        }
    }

    return files;
}

void save_encrypted_file(const std::string &path,
                         const std::vector<uint8_t> &data,
                         const std::vector<uint8_t> &nonce,
                         const std::vector<uint8_t> &tag)
{
    std::ofstream out(path, std::ios::binary);
    if (!out)
        return;

    out.write(reinterpret_cast<const char *>(nonce.data()), nonce.size());
    out.write(reinterpret_cast<const char *>(tag.data()), tag.size());
    out.write(reinterpret_cast<const char *>(data.data()), data.size());
}

std::vector<uint8_t> aes_gcm_decrypt(
    const std::vector<uint8_t> &ciphertext,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonce,
    const std::vector<uint8_t> &tag)
{
    std::vector<uint8_t> plaintext(ciphertext.size());
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    if (!ctx)
        return {};

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), NULL))
    {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void *)tag.data()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        return plaintext;
    }

    // Auth tag failed, decryption failed
    return {};
}
bool restore_file(const std::string &encrypted_file_path, const std::string &restore_path)
{
    // Read full file
    std::ifstream fin(encrypted_file_path, std::ios::binary);
    if (!fin)
    {
        std::cerr << "[-] Failed to open encrypted file: " << encrypted_file_path << "\n";
        return false;
    }

    std::vector<uint8_t> file_data((std::istreambuf_iterator<char>(fin)), {});
    fin.close();

    // Extract nonce, tag, ciphertext from file
    const size_t nonce_len = 12; // Typical GCM nonce
    const size_t tag_len = 16;

    if (file_data.size() < nonce_len + tag_len)
    {
        std::cerr << "[-] Encrypted file too small or corrupted\n";
        return false;
    }

    std::vector<uint8_t> nonce(file_data.begin(), file_data.begin() + nonce_len);
    std::vector<uint8_t> tag(file_data.begin() + nonce_len, file_data.begin() + nonce_len + tag_len);
    std::vector<uint8_t> ciphertext(file_data.begin() + nonce_len + tag_len, file_data.end());

    std::vector<uint8_t> plaintext = aes_gcm_decrypt(ciphertext, get_fixed_aes_key(), nonce, tag);

    if (plaintext.empty())
    {
        std::cerr << "[-] Failed to decrypt file. Possibly wrong key or file corrupted\n";
        return false;
    }

    // Save restored file
    std::ofstream fout(restore_path, std::ios::binary);
    fout.write(reinterpret_cast<const char *>(plaintext.data()), plaintext.size());
    fout.close();

    std::cout << "[+] File restored to: " << restore_path << "\n";
    return true;
}
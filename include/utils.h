#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <cstdint>

std::string sha256_file(const std::string &path);
std::vector<uint8_t> read_file_binary(const std::string &path);
std::string get_filename(const std::string &path);
double calculate_entropy(const std::vector<uint8_t> &data);
void save_encrypted_file(const std::string &path,
                         const std::vector<uint8_t> &data,
                         const std::vector<uint8_t> &nonce,
                         const std::vector<uint8_t> &tag);
std::vector<std::string> collect_files(const std::string &path);
std::vector<uint8_t> aes_gcm_decrypt(
    const std::vector<uint8_t> &ciphertext,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonce,
    const std::vector<uint8_t> &tag);
bool restore_file(const std::string &encrypted_file_path, const std::string &restore_path);

#endif

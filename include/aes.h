#ifndef AES_H
#define AES_H

#include <vector>
#include <cstdint>

std::vector<uint8_t> aes_gcm_encrypt(const std::vector<uint8_t> &plaintext,
                                     const std::vector<uint8_t> &key,
                                     std::vector<uint8_t> &nonce,
                                     std::vector<uint8_t> &tag);

std::vector<uint8_t> get_fixed_aes_key();

#endif

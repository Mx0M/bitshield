#include "aes.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>

std::vector<uint8_t> aes_gcm_encrypt(const std::vector<uint8_t> &plaintext,
                                     const std::vector<uint8_t> &key,
                                     std::vector<uint8_t> &nonce,
                                     std::vector<uint8_t> &tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    nonce.resize(12);
    RAND_bytes(nonce.data(), 12);

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());

    std::vector<uint8_t> ciphertext(plaintext.size());
    int len;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    int ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    tag.resize(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::vector<uint8_t> get_fixed_aes_key()
{
    return std::vector<uint8_t>(32, 0x23); // Fixed 256-bit key (for demo purposes)
}

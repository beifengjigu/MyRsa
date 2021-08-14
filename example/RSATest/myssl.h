#ifndef MYSSL_H
#define MYSSL_H
#include <bits/stdc++.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#define KEY_LENGTH  1024

#define PUBLICKEY "../keys/rsa_public_key.pem"
#define PRIVATEKEY "../keys/rsa_private_key.pem"
class MySsl
{
private:
    std::string privatekey;
    std::string publickey;
    RSA* rsa_private_key = NULL; // 需要读取的rsa私钥
    RSA* rsa_public_key = NULL; // 需要读取的rsa公钥
public:
    MySsl();
    bool GenerateKey();
    bool load_RSA_keys();
    std::string GetPrivateKey();
    std::string GetPublicKey();
    std::string Encryption(std::string plaintext,std::string key);//加密函数，使用时需要提供明文和密钥
    std::string Encryption(std::string plaintext);//加密函数，使用时需要提供明文和密钥
    std::string Decrypt(std::string ciphertext,std::string key,int length);//解密函数
    std::string Decrypt(std::string ciphertext,int length);//重载解密函数，默认使用本地的rsa密钥解密
    std::string Hash(std::string input);

};

#endif // MYSSL_H

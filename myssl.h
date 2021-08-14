#ifndef MYSSL_H
#define MYSSL_H
#include <bits/stdc++.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#define KEY_LENGTH  128
#define PADDING 11

#define PUBLICKEY "../keys/rsa_public_key.pem"
#define PRIVATEKEY "../keys/rsa_private_key.pem"

class MySsl
{
private:
    std::string privatekey;
    std::string publickey;
    RSA* rsa_private_key = NULL; //this is use for load key's file
    RSA* rsa_public_key = NULL; //this is use for load key's file
public:
    MySsl();
    bool GenerateKey();
    bool load_RSA_keys();
    std::string GetPrivateKey();
    std::string GetPublicKey();
    std::string Encryption(std::string plaintext);
    std::string Encryption(std::string plaintext,std::string key);
    std::string Decrypt(std::string ciphertext,std::string key,int length);
    std::string Decrypt(std::string ciphertext,int length);
    std::string Hash(std::string input);

};

#endif // MYSSL_H

#include "myssl.h"

MySsl::MySsl()
{

}
bool MySsl::load_RSA_keys() {
    FILE *file=NULL;
    file = fopen(PUBLICKEY,"r");
    if (file== NULL) {
        fclose(file);
        return false;
    }
    rsa_public_key = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);
    if(rsa_public_key==NULL){
     fclose(file);
     return false;
    }
    fclose(file);
    //读取公钥
    FILE *newfile=NULL;
    newfile=fopen(PRIVATEKEY,"r");
    if(newfile==NULL){
        fclose(file);
        return false;
    }
    rsa_private_key = PEM_read_RSAPrivateKey(newfile, NULL, NULL, NULL);
    if(rsa_private_key==NULL){
      fclose(newfile);   
      return false;
    }
    fclose(newfile);
    //读取私钥
    return true;
}
bool MySsl::GenerateKey()
{
    size_t pri_len;
    size_t pub_len;
    char *pri_key = NULL;
    char *pub_key = NULL;

    // 生成密钥对
    RSA *keypair = RSA_generate_key(KEY_LENGTH, RSA_F4, NULL, NULL);

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    // 获取长度
    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    // 密钥对读取到字符串
    pri_key = (char *)malloc(pri_len + 1);
    pub_key = (char *)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    this->privatekey=std::string(pri_key);
    this->publickey=std::string(pub_key);

    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);

    free(pri_key);
    free(pub_key);
}

std::string MySsl::GetPrivateKey()
{
    return this->privatekey;
}

std::string MySsl::GetPublicKey()
{
    return this->publickey;
}

std::string MySsl::Encryption(std::string plaintext,std::string key)
{
//首先需要判断输入的是公钥还是私钥，判断完成后根据类型进行修改
    RSA* rsa=RSA_new();
    BIO *keybio = BIO_new_mem_buf((unsigned char *)key.c_str(), -1);
    const std::string publickey1_flag="-----BEGIN RSA PUBLIC KEY-----";
    const std::string publickey8_flag="-----BEGIN PUBLIC KEY-----";
    if(std::strncmp(key.c_str(),publickey1_flag.c_str(),publickey1_flag.length())==0){
        rsa=PEM_read_bio_RSAPublicKey(keybio,NULL,NULL,NULL);
    }else if(std::strncmp(key.c_str(),publickey8_flag.c_str(),publickey8_flag.length())==0){
        rsa=PEM_read_bio_RSA_PUBKEY(keybio,NULL,NULL,NULL);
    }else{
        rsa=PEM_read_bio_RSAPrivateKey(keybio,NULL,NULL,NULL);
    }
    int rsa_len = RSA_size(rsa);
    int slice_max=rsa_len-11;
    int nums=plaintext.length()/slice_max;
    if(plaintext.length()%slice_max!=0){
        nums+=1;
    }
    int all_len=rsa_len*nums;
    //
    std::cout<<all_len<<std::endl;
    unsigned char *encryptMsg = (unsigned char *)malloc(all_len);
    memset(encryptMsg, 0, rsa_len);

    for(int i=0;i<nums-1;i++){
        if (RSA_public_encrypt(slice_max, (unsigned char *)plaintext.c_str()+i*slice_max,encryptMsg+rsa_len*i, rsa, RSA_PKCS1_PADDING) < 0){
            return "false";
        }
    }
    if(plaintext.length()!=0){
        int end_len=plaintext.length()%slice_max;
        if(end_len==0) end_len=slice_max;
        if (RSA_public_encrypt(end_len, (unsigned char *)plaintext.c_str()+(nums-1)*slice_max,encryptMsg+rsa_len*(nums-1), rsa, RSA_PKCS1_PADDING) < 0){
            return "false";
        }
    }
    std::string returnVal((char *) encryptMsg, all_len);
    free(encryptMsg);
    BIO_free(keybio);
    RSA_free(rsa);
    return returnVal;
    //切片
    //每片长度应该等于rsa_len-2
}
std::string MySsl::Encryption(std::string plaintext)
{
//首先需要判断输入的是公钥还是私钥，判断完成后根据类型进行修改
    RSA* rsa=this->rsa_public_key;
    
    int rsa_len = RSA_size(rsa);
    int slice_max=rsa_len-11;
    int nums=plaintext.length()/slice_max;
    if(plaintext.length()%slice_max!=0){
        nums+=1;
    }
    int all_len=rsa_len*nums;
    //
    std::cout<<all_len<<std::endl;
    unsigned char *encryptMsg = (unsigned char *)malloc(all_len);
    memset(encryptMsg, 0, rsa_len);

    for(int i=0;i<nums-1;i++){
        if (RSA_public_encrypt(slice_max, (unsigned char *)plaintext.c_str()+i*slice_max,encryptMsg+rsa_len*i, rsa, RSA_PKCS1_PADDING) < 0){
            return "false";
        }
    }
    if(plaintext.length()!=0){
        int end_len=plaintext.length()%slice_max;
        if(end_len==0) end_len=slice_max;
        if (RSA_public_encrypt(end_len, (unsigned char *)plaintext.c_str()+(nums-1)*slice_max,encryptMsg+rsa_len*(nums-1), rsa, RSA_PKCS1_PADDING) < 0){
            return "false";
        }
    }
    std::string returnVal((char *) encryptMsg, all_len);
    free(encryptMsg);
    return returnVal;
    //切片
    //每片长度应该等于rsa_len-2
}

std::string MySsl::Decrypt(std::string ciphertext,std::string key,int length)
{
    RSA* rsa=RSA_new();
    BIO *keybio = BIO_new_mem_buf((unsigned char *)key.c_str(), -1);
    const std::string publickey_flag="-----BEGIN RSA PUBLIC KEY-----";
    if(std::strncmp(key.c_str(),publickey_flag.c_str(),publickey_flag.length())==0){
        rsa=PEM_read_bio_RSAPublicKey(keybio,NULL,NULL,NULL);
    }else{
        rsa=PEM_read_bio_RSAPrivateKey(keybio,NULL,NULL,NULL);
    }
    int rsa_len = RSA_size(rsa);
    int slice_max=rsa_len-11;
    int nums=ciphertext.length()/rsa_len;
    int all_len=nums*slice_max;

    unsigned char *decryptMsg = (unsigned char *)malloc(all_len);
    std::memset(decryptMsg, 0, all_len);

    for(int i=0;i<nums;i++){
        if (RSA_private_decrypt(rsa_len, (u_char *)ciphertext.c_str()+i*rsa_len, decryptMsg+slice_max*i,rsa, RSA_PKCS1_PADDING) < 0){
            return "false";
        }
    }
    std::string returnVal((char *) decryptMsg,length);
    free(decryptMsg);
    BIO_free(keybio);
    RSA_free(rsa);
    return returnVal;
}
std::string MySsl::Decrypt(std::string ciphertext,int length){
    RSA* rsa=this->rsa_private_key;
    int rsa_len = RSA_size(rsa);
    int slice_max=rsa_len-11;
    int nums=ciphertext.length()/rsa_len;
    int all_len=nums*slice_max;

    unsigned char *decryptMsg = (unsigned char *)malloc(all_len);
    std::memset(decryptMsg, 0, all_len);

    for(int i=0;i<nums;i++){
        if (RSA_private_decrypt(rsa_len, (u_char *)ciphertext.c_str()+i*rsa_len, decryptMsg+slice_max*i,rsa, RSA_PKCS1_PADDING) < 0){
            return "false";
        }
    }
    std::string returnVal((char *) decryptMsg,length);
    free(decryptMsg);
    return returnVal;
}
std::string MySsl::Hash(std::string input){
    unsigned char sha1_digest[SHA_DIGEST_LENGTH] = {0};
    SHA1(reinterpret_cast<const unsigned char *> (input.c_str()), input.length(), sha1_digest);
    //reinterpret_cast是一种基于bit的强制类型转换
    char buffout[SHA_DIGEST_LENGTH * 4] = {0};
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(buffout + i * 2, "%02x", sha1_digest[i]);
        // X 表示以十六进制形式输出
        // 02 表示不足两位，前面补0输出；如果超过两位，则实际输出
    }
    return buffout;
}

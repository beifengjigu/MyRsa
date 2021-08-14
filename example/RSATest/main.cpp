#include "myssl.h"
#include<iostream>
#include<string>
#include<cstring>

int main(){
    MySsl myssl;
    myssl.load_RSA_keys();
    char buffer[2048];
    std::memset(buffer,0,1025*sizeof(char));
    std::string a("sanvcudvnousfdbvifdsbvlibfdsvlhbfdslhvbdfuhvbfdhvbdlhfvblhfdvblihdfbvlifdbvlifdsbnlihfdblihfdbluhvbfdlihvbfdihlvbdlihvbnkbdsnlijcbdsjcbds;ijcbndskjcvbfdlihjvbflihvbflhvblihfvblihfvblihfdbvhlijfdvhlfdbvlfdsbnlihrdsbnlihjrebhjfd vkjfdn vlkjsnchjdsnckjdsbncihjdsbnkjmissyou");
    std::strcpy(buffer,a.c_str());
    std::string plaintext(buffer);
    std::string entext=myssl.Encryption(plaintext);
    std::cout<<entext.c_str()<<std::endl;
    std::cout<<myssl.Decrypt(entext,a.length())<<std::endl;
    std::cout<<myssl.Hash("hello world")<<std::endl;
    return 0;
}
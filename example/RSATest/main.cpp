#include "myssl.h"
#include<iostream>
#include<string>
#include<cstring>
struct Test{
    int type;
    char msg[128];
    char hash[SHA_DIGEST_LENGTH*4];
};
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
    //this is the string example

    Msg_Data msg;
    std::memset(&msg,0,sizeof(msg));
    Test test;
    std::memset(&test,0,sizeof(test));
    test.type=1;
    std::strcpy(test.msg,"hello this is test string");
    std::strcpy(test.hash,myssl.Hash(std::string(test.msg)).c_str());
    std::cout<<test.hash<<std::endl;
    std::string beforestr((char*)&test,sizeof(test));

    std::string afterstr=myssl.Encryption(beforestr);

    std::memcpy(&msg.msg,afterstr.c_str(),afterstr.length()*sizeof(char));

    msg.beforelength=beforestr.length();
    msg.afterlength=afterstr.length();

    Test back;
    std::memset(&back,0,sizeof(back));

    std::string backstr=myssl.Decrypt(std::string((char*)&msg.msg,msg.afterlength*sizeof(char)),msg.beforelength);

    std::memcpy(&back,backstr.c_str(),sizeof(back));
    std::cout<<back.type<<std::endl;
    std::cout<<back.msg<<std::endl;
    std::cout<<back.hash<<std::endl;


    //this is the struct data example
    return 0;
}
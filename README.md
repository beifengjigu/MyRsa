# MyRsa
This is c++ class for RSA encrypt and decrypt.Easy for use and can encrypt and decrypt long string(much longer than key's length).

## prepare
under Ubuntu,Debian and Deepin or UOS,you should install openssl and libssl-dev first
```shell
sudo apt install openssl libssl-dev
```
## use
### functions
#### load_RSA_Keys
this function read key files and generate RSA class pointer
if you want to use key file,you should run it before encrypt and decrypt
you can change the myssl's define to change the key files' path
#### GenerateKey
this function generate keys and store them in two strings,if you want to user random keys,this function is useful
#### Encryption/Decrypt
you can use encryption function to encrypt very long string,if you want to encrypt struct data,you should read example code,this can help you.
the length in Decrypt function is set the output length,for example,
you encrypt a string but you should get the string's length and put it in Decrypt funtion or you will get some strange chars after the true string
### make
you should add 
-lssl -lm -lcrypto
in your complie command
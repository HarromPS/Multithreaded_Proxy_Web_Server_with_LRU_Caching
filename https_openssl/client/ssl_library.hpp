// header file to declare tasks to perform 

#include<openssl/bio.h> // basic input output streams
#include<openssl/ssl.h> // core library
#include<openssl/err.h> // error library

#ifndef SSL_UTILS_HPP
#define SSL_UTILS_HPP

// namespace for funtions
namespace ssl{
    // initialize ssl libraries 
    void initSSL();

    // report and error functions
    void reportErrors(const char* err);

    // SSL setup, creating a ssl context 
    SSL_CTX* createSSLContext(const char* certFile);
}

#endif
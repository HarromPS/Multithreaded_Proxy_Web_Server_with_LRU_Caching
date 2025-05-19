// header file to declare tasks to perform 

#include<iostream>
#include<openssl/bio.h> // basic input output streams
#include<openssl/ssl.h> // core library
#include<openssl/err.h> // error library
#include "./ssl_library.hpp"

#define CACHE_ID "OpenSSL server"

// namespace for funtions
namespace ssl{
    // initialize ssl libraries 
    void initSSL(){
        SSL_library_init();
        SSL_load_error_strings();
    }

    // report and error functions
    void reportErrors(const char* err){
        fprintf(stderr,err);
        ERR_print_errors_fp(stderr);
    }

    // SSL setup, creating a ssl context 
    SSL_CTX* createSSLContext(const char* certFile){
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            std::cerr << "Unable to create SSL_CTX\n";
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        // SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

        // specifies the locations for ctx, at which CA certificates for verification are located
        // to trust server cert, verify it
        if (SSL_CTX_load_verify_locations(ctx,certFile, NULL)==0) {
            std::cerr << "Failed to load server certificate as a trusted certificate\n";
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

        if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
            std::cerr << "Failed to set the minimum TLS protocol version\n";
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

        return ctx;

    }
}

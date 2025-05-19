// header file to declare tasks to perform 

#include<iostream>
#include<openssl/bio.h> // basic input output streams
#include<openssl/ssl.h> // core library
#include<openssl/err.h> // error library

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
    SSL_CTX* createSSLContext(const char* certFile, const char* keyFile){
        // creating a ssl context 
        SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) {
            std::cerr << "Unable to create SSL_CTX\n";
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

        // at least set to the min version of tcp protocol
        if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
            std::cerr << "Failed to set the minimum TLS protocol version\n";
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

        // verify certificate 
        if (SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) <= 0) {
            std::cerr << "Failed to load certificate file\n";
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

        // verify secret key file
        if (SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0) {
            std::cerr << "Error loading server private key file\n";
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

        // resuing the session for ctx object 
        if(SSL_CTX_set_session_id_context(
            ctx, 
            reinterpret_cast<const unsigned char *>(CACHE_ID),  // reinterpret char* as char pointer
            sizeof(CACHE_ID)) == 0)
        {
            std::cerr << "Error logged file\n";
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

        // enabling session caching 
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER); // enables server-side session caching

        // set cache size
        SSL_CTX_sess_set_cache_size(ctx, 1024);  // how many client TLS sessions to cache

        SSL_CTX_set_timeout(ctx, 3600);  // sessions older than this are considered a cache miss even if still in the cache

        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);  // client cert auth not needed

        return ctx;
    }
}

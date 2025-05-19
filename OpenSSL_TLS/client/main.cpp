// #include <arpa/inet.h>
// #include <netinet/in.h>
// #include <sys/socket.h>
// #include <unistd.h>

// #include <cerrno>
// #include <cstring>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <iostream>

#include <openssl/bio.h> // basic input output streams
#include <openssl/ssl.h> // core library
#include <openssl/err.h>
#include "ssl_library.hpp"
#include "BIO_Utils.hpp"

#define BUFFER_SIZE 4096
#define CHUNK_SIZE 16384

#define cert "./server.pem"
#define key "./server.key"

// int PORT;
char *PORT;
char *hostname;

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <server_hostname> <server_portnum>"
                  << "\n";
        return 1;
    }

    hostname = argv[1];
    // PORT = atoi(argv[2]);
    PORT = argv[2];

    SSL_CTX *ctx = ssl::createSSLContext(cert,key);

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        std::cerr << "Failed to create the SSL object\n";
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // making connection using bio wrapped sockets with the remote server
    BIO *bio = bio::create_socket_bio(hostname, PORT, AF_INET);     // ipv4 address family
    if (bio == NULL) {
        std::cerr << "Failed to create the BIO\n";
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // wrap ssl context on tcp socket 
    SSL_set_bio(ssl, bio, bio);         // read and write on the same bio

    // Tell the server during the handshake which hostname we are attempting to connect to in case the server supports multiple hosts.
    if (!SSL_set_tlsext_host_name(ssl, hostname)) {
        std::cerr << "Failed to set the SNI hostname\n";
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Ensure we check during certificate verification that the server has supplied a certificate for the hostname that we were expecting.
    if (!SSL_set1_host(ssl, hostname)) {
        std::cerr << "Failed to set the certificate verification hostname\n";
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    int nodelay_flag = 1;
    int client_fd;
    client_fd = SSL_get_fd(ssl);
    if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay_flag, sizeof(nodelay_flag)) == -1) {
        // std::cerr << "Failed to enable TCP_NODELAY: " << std::strerror(errno) << "\n";
    }
    // std::cout<<"Disabled Nagles' algorithm\n";

    /* Do the handshake with the server */
    if (SSL_connect(ssl) < 1) {
        std::cerr << "Failed to connect to the server\n";
        /*
         * If the failure is due to a verification error we can get more
         * information about it from SSL_get_verify_result().
         */
        if (SSL_get_verify_result(ssl) != X509_V_OK) printf("Verify error: %s\n", X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    std::cout << "Connected to server:\n";

    // make the request 
    const char* request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    SSL_write(ssl, request, strlen(request));

    // read the response
    char buffer[1024];
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("Server replied: %s\n", buffer);
    }

    // handlers::serverHandler(sockfd);

    // handlers::serverHandler(ssl);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
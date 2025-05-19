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
#include <regex>
#include <string>
#include <sstream>

#include <openssl/bio.h> // basic input output streams
#include <openssl/ssl.h> // core library
#include <openssl/err.h>
#include "ssl_library.hpp"
#include "BIO_Utils.hpp"

#define BUFFER_SIZE 4096
#define CHUNK_SIZE 16384

#define cert "./server.pem"

// int PORT;
char *PORT;
char *hostname;

std::string build_proxy_request(const std::string& url) {
    std::regex url_regex(R"((https?)://([^/:]+)(?::(\d+))?(\/.*)?)");
    std::smatch match;

    if (!std::regex_match(url, match, url_regex)) {
        throw std::runtime_error("Invalid URL format.");
    }

    std::string scheme = match[1];
    std::string host = match[2];
    std::string port = match[3].matched ? match[3].str() : (scheme == "https" ? "443" : "80");
    std::string path = match[4].matched ? match[4].str() : "/";

    std::ostringstream request;

    if (scheme == "http") {
        request << "GET " << url << " HTTP/1.1\r\n";
        request << "Host: " << host << "\r\n";
        request << "User-Agent: curl/8.5.0\r\n";
        request << "Accept: */*\r\n";
        request << "Proxy-Connection: Keep-Alive\r\n\r\n";
    } else if (scheme == "https") {
        request << "CONNECT " << host << ":" << port << " HTTP/1.1\r\n";
        request << "Host: " << host << ":" << port << "\r\n";
        request << "User-Agent: curl/8.5.0\r\n";
        request << "Proxy-Connection: Keep-Alive\r\n\r\n";
    }

    return request.str();
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <server_hostname> <server_portnum>"
                  << "\n";
        return 1;
    }

    hostname = argv[1];
    // PORT = atoi(argv[2]);
    PORT = argv[2];

    SSL_CTX *ctx = ssl::createSSLContext(cert);

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

    // handle type of connection user wants with the server
    std::string url;
    std::cout << "Enter URL: ";
    std::getline(std::cin, url);

    try {
        std::string proxy_request = build_proxy_request(url);
        std::cout << "Generated proxy request:\n" << proxy_request << std::endl;
        
        // Write the request in chunks to ensure it's all sent
        const char* request_ptr = proxy_request.c_str();
        size_t total_sent = 0;
        size_t remaining = proxy_request.size();
        
        while (remaining > 0) {
            int write_result = SSL_write(ssl, request_ptr + total_sent, remaining);
            if (write_result <= 0) {
                int ssl_error = SSL_get_error(ssl, write_result);
                std::cerr << "SSL_write failed with error: " << ssl_error << std::endl;
                ERR_print_errors_fp(stderr);
                break;
            }
            total_sent += write_result;
            remaining -= write_result;
        }
        
        std::cout << "Total bytes sent: " << total_sent << std::endl;
    
        // Wait for the response with proper timeout
        fd_set readfds;
        struct timeval tv;
        tv.tv_sec = 5;  // 5 seconds timeout
        tv.tv_usec = 0;
        
        int sockfd = SSL_get_fd(ssl);
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        
        int select_result = select(sockfd + 1, &readfds, NULL, NULL, &tv);
        if (select_result == -1) {
            std::cerr << "Select error" << std::endl;
        } else if (select_result == 0) {
            std::cerr << "Timeout waiting for response" << std::endl;
        } else {
            // Read the response
            char buffer[4096];
            int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                std::cout << "Server replied: " << std::endl;
                std::cout << buffer << std::endl;

                std::string https_req = "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
                SSL_write(ssl, https_req.c_str(), https_req.size());

                while ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
                    buffer[bytes] = '\0';
                    std::cout << buffer;
                }

            } else {
                std::cerr << "SSL_read failed with error: " << SSL_get_error(ssl, bytes) << std::endl;
                ERR_print_errors_fp(stderr);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error parsing URL: " << e.what() << std::endl;
    }

    // // make the request 
    // const char* request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    // SSL_write(ssl, request, strlen(request));

    
    // read the response
    // char buffer[1024];
    // int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    // if (bytes > 0) {
    //     buffer[bytes] = '\0';
    //     printf("Server replied: %s\n", buffer);
    // }

    // handlers::serverHandler(sockfd);

    // handlers::serverHandler(ssl);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
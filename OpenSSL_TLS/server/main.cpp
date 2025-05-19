/*
OPENSSL/TLS library 
- performs ssl handshake with client for amd establishes tcp connection 
- provides secure communication 
- wraps socket with ssl layer to add security
- encrypts data and handles certificates, handshakes & key exchanges
- works on top of sockets 
- connect() method is implemented internally but adds TLS/SSL
*/

#include<iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <cstring>
#include <sys/types.h>
#include <openssl/bio.h> // basic input output streams
#include <openssl/ssl.h> // core library
#include <openssl/err.h>
#include "ssl_library.hpp"

// .pem .cer .cret are used interchangeable

#define cert "./server.pem"
#define key "./server.key"

int main(int argCount, char* argValue[]){
    // check if port provided
    if(argCount!=2){
        fprintf(stderr,"Too few arguments\n");
        return 1;
    }

    const char* port = argValue[1];

    // 1. initialize ssl context, library
    ssl::initSSL();

    // 2. create ssl context, then wrap on tcp socket via bio or ssl set fd
    SSL_CTX* ctx = ssl::createSSLContext(cert,key);

    // sockets 
    // BIO acceptor(basic i/o stream) ssl enabled socket listener
    // BIO is a layer on socket or memory to read and write data on without handling row sockets

    // create a tcp socket (new + set_accept_name) -> socket 
    BIO* acceptor_bio = BIO_new_accept(port);
    if(!acceptor_bio){
        ssl::reportErrors("Error creating acceptor BIO\n");
        SSL_CTX_free(ctx);
        return 1;
    }

    // 3. bind io with port and listen connections
    BIO_set_bind_mode(acceptor_bio, BIO_BIND_REUSEADDR);
    if(BIO_do_accept(acceptor_bio) <= 0){                                      // setsockopt() + bind() + listen()
        ssl::reportErrors("Error setting acceptor socket\n");
        SSL_CTX_free(ctx);
        return 1;
    }

    int serverSocket;

    // returns a file descriptor to server socket 
    if(BIO_get_fd(acceptor_bio, &serverSocket) == -1){    // create server socket with bio acceptor socket 
        ssl::reportErrors("BIO has failed to intialized");
        SSL_CTX_free(ctx);
        return 1;
    }

    // disabling nagles algo
    int noDelayFlag=1;

    // 4. set tcp socket options 
    if(setsockopt(
        serverSocket, 
        IPPROTO_TCP,            // returns a TCP socket 
        TCP_NODELAY,            // disabling nagles algo 
        (char*)&noDelayFlag,
        sizeof(noDelayFlag)
    ) == -1){
        ssl::reportErrors("Falied to set TCP_NODELAY\n");
        return 1;
    }

    // fprintf(stderr,"Disabled Nagles algorithm\n");
    std::cout<<"Server listening to port: "<<port<<std::endl;

    // 5. accept and handle clients
    while(true){
        BIO* clientBIO = nullptr;               // bio for client socket 
        SSL* ssl = nullptr;                     // ssl object as a wrapper on raw socket as a secure layer

        // wait for client to connect, to this server address and port
        if(BIO_do_accept(acceptor_bio) <= 0){
            ssl::reportErrors("Error accepting client connections");
            continue;
        }

        // when there is a client, pop client connection from bio chain
        // pop client socket 
        clientBIO = BIO_pop(acceptor_bio);
        if(!clientBIO){
            ssl::reportErrors("Error popping client BIO\n");
            continue;
        }

        // get the client address 
        struct sockaddr_storage clientAddr;         // object to store socket address information 
        socklen_t addrLen = sizeof(clientAddr);     // get the size of socket address structure 32 bit in size 
        
        int clientSocket;
        if(BIO_get_fd(clientBIO, &clientSocket) == -1){       // returns client socket file descriptor
            ssl::reportErrors("BIO has failed to intialized\n");
            continue; 
        }

        // retrive address and port of peer socket and save to sockadd struct pointed to by the address argument
        if(getpeername(clientSocket,(struct sockaddr*)&clientAddr, &addrLen) == -1){
            ssl::reportErrors("Error fetching name of peer socket\n");
            continue;
        }

        char clientIPAddress[INET_ADDRSTRLEN];    // ipv4 address length
        int clientPort;

        // get the internet address and convert to host address
        struct sockaddr_in* internetAddress  = (struct sockaddr_in*)&clientAddr;
        inet_ntop(AF_INET, &internetAddress->sin_addr, clientIPAddress, INET_ADDRSTRLEN);
        clientPort = ntohs(internetAddress->sin_port);

        std::cout<<"Client connected to IP: "<<clientIPAddress<<" at port: "<<clientPort<<std::endl;

        // wrap ssl 
        // associate a new SSL structure with new client
        if((ssl = SSL_new(ctx)) == NULL){
            ssl::reportErrors("Error creating SSL handle for new connection\n");
            BIO_free(clientBIO);
            continue;
        }

        // connect bios read and write bios operation of TLS/SSL side of ssl 
        // transfer ownership of clientBIO to ssl object 
        SSL_set_bio(ssl, clientBIO, clientBIO);

        // attempt an ssl handshake with the client 
        if(SSL_accept(ssl) <= 0){
            ssl::reportErrors("Error in attempting a SSL handshake with the client\n");
            // BIO_free(clientBIO);    // double free
            SSL_free(ssl);
            continue;
        }

        // read the client data 
        char buffer[1024];
        int bytes = SSL_read(ssl,buffer,sizeof(buffer));
        if(bytes>0){
            buffer[bytes]='\0';     // nullify the buffer at last index 

            // generate the response 
            const char* response =  "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nSecure Hello From server!";

            // write response back to the client 
            SSL_write(ssl,response,strlen(response));
        }

        std::cout<<"SSL handshake is successful with client from IP: "<<clientIPAddress<<", at port: "<<clientPort<<std::endl;

        // close client connection 
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ctx);
    BIO_free_all(acceptor_bio); 
    return 0;
}
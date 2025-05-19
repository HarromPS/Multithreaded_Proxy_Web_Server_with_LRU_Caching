// C++ program to show the example of server application in
// socket programming
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <thread>
#include <openssl/bio.h> // basic input output streams
#include <openssl/ssl.h> // core library
#include <openssl/err.h>
#include "./headers/proxy_utils.hpp"
#include "./headers/proxy_parse.h"
#include "./headers/ssl_library.hpp"

#define MAX_CLIENTS 10
#define MAX_BYTES 100    // max allowed size of request/response
#define _1K (1<<10)          // 1k i.e 1024
#define MAX_CACHE_ELEMENT_SIZE (30*_1K) // 30K
#define MAX_CACHE_SIZE (200*_1K) // 200K

#define cert "./files/server.pem"
#define key "./files/server.key"

// create a Handler object here
Handler* handler = new Handler(MAX_CLIENTS, MAX_BYTES, MAX_CACHE_ELEMENT_SIZE, MAX_CACHE_SIZE);

void* handleClient(void* arguments)
{
    // acquire semaphore
    handler->sem.acquire();
    int p;
    handler->sem.getValue(&p);
    std::cout<<"semaphore value is:"<<p<<std::endl;

    struct args *threadArgs = (struct args *)arguments;
    char* ipAddress = threadArgs->ipAddress;
    int socket = threadArgs->connectedSocketId;  // create a copy of client socket file descriptor 
    SSL* threadSsl = threadArgs->ssl;
    

    int number_of_bytes_send_by_client=0, total_received_bytes_from_client=0;
    std::cout << "Thread started for socket: " << socket << std::endl;

    // create a buffer of max bytes of type char 
    int MAX_BUFFER = MAX_BYTES;
    char* buffer = (char*)calloc(MAX_BUFFER,sizeof(char));
    memset(buffer, 0, MAX_BUFFER);

    // PERFORMING SSL READ AND WRITE OPERATIONS INSTEAD OF RAW READ AND WRITE OPERATIONS
    number_of_bytes_send_by_client = SSL_read(threadSsl,buffer,MAX_BUFFER);
    
    // check for recv return value and handle that properly
    if(number_of_bytes_send_by_client < 0){
        fprintf(stderr,"Error receiving data from client\n");
        shutdown(socket, SHUT_RDWR);
        free(buffer);
        handler->sem.release();
        handler->sem.getValue(&p);
        std::cout<<"Semaphore value is: "<<p<<std::endl;
        return NULL;
    }
    else if(number_of_bytes_send_by_client == 0){
        fprintf(stderr,"Connection Closed\n");
        shutdown(socket, SHUT_RDWR);
        free(buffer);
        handler->sem.release();
        handler->sem.getValue(&p);
        std::cout<<"Semaphore value is: "<<p<<std::endl;
        return NULL;
    }

    // receive until full request is received 
    while(number_of_bytes_send_by_client > 0){
        total_received_bytes_from_client  += number_of_bytes_send_by_client;

        // if total message received is more than max bytes limit, reallocate double memory size to buffer
        if(total_received_bytes_from_client >= MAX_BUFFER){
            MAX_BUFFER *= 2;    // double the size
            char* new_buffer = (char*)realloc(buffer, MAX_BUFFER);
            if(new_buffer == NULL){
                fprintf(stderr,"Error reallocating memory\n");
                free(buffer);
                free(new_buffer);
                handler->sem.release();
                handler->sem.getValue(&p);
                std::cout<<"Semaphore value is: "<<p<<std::endl;
                return NULL;
            }
            else{
                buffer = new_buffer;
            }
        }

        buffer[total_received_bytes_from_client] = '\0';
        // check if http termination sequence is found
        if(strstr(buffer,"\r\n\r\n") == NULL){  
            // each time buffer size doubles to receive data
            number_of_bytes_send_by_client = SSL_read(threadSsl, 
                buffer+total_received_bytes_from_client,
                MAX_BUFFER-total_received_bytes_from_client);

            // error handling while receiving data from client
            if(number_of_bytes_send_by_client < 0){
                fprintf(stderr,"Error receiving data from client\n");
                shutdown(socket, SHUT_RDWR);
                free(buffer);
                handler->sem.release();
                handler->sem.getValue(&p);
                std::cout<<"Semaphore value is: "<<p<<std::endl;
                return NULL;
            }
            else if(number_of_bytes_send_by_client == 0){
                fprintf(stderr,"Connection Closed\n");
                shutdown(socket, SHUT_RDWR);
                free(buffer);
                handler->sem.release();
                handler->sem.getValue(&p);
                std::cout<<"Semaphore value is: "<<p<<std::endl;
                return NULL;
            }
        }
        else{
            break;
        }
    }

    // create a copy of buffer 
    int bufferLength = strlen(buffer) + 1;  // 1 for null terminator
    char* tempRequest = (char*)malloc((sizeof(char)*bufferLength)+1);
    strcpy(tempRequest, buffer);
    tempRequest[bufferLength]='\0'; // add null terminator character
    
    for(int i=0;i<bufferLength;i++){
        std::cout<<tempRequest[i];
    }
    std::cout<<std::endl;


    // check if there is request from client 
    if(number_of_bytes_send_by_client > 0){
        total_received_bytes_from_client = strlen(buffer);

        std::cout<<"SSL handshake is successful with client from IP: "<<ipAddress<<std::endl; // <<", at port: "<<clientPort<<std::endl;

        // check if this is a CONNECT METHOD
        std::string req(buffer, bufferLength);
        // std::cout<<req<<std::endl;

        if(req.find("CONNECT") == 0){
            // handle connect requests
            handler->handleConnectMethod(req, socket, handler->log_stream, threadSsl);
        }else{        
            // parse the client request 
            ParsedRequest* request = ParsedRequest_create();

            if(ParsedRequest_parse(request,tempRequest,total_received_bytes_from_client) < 0){
                std::cout<<"Parsing Failed"<<std::endl;
                // close socket 
                shutdown(socket,SHUT_RDWR);     // No more receptions or transmissions
                close(socket);

                // free allocated memory 
                ParsedRequest_destroy(request);
                free(buffer);
                free(tempRequest);

                handler->sem.release();
                handler->sem.getValue(&p);
                std::cout<<"Semaphore value is: "<<p<<std::endl;

                // Gracefully exit function instead of abrupt exit(1)
                return NULL;
            }
            else{
                
                // check element is in the cache 
                // memory leaked on url creation
                // char* url = (char*)malloc(sizeof(char)*strlen(request->host));
                // strcpy(url,request->host);
                // strcat(url,request->path);

                // fixed memory leak
                // host + path + 1 for null terminator character
                char* url = (char*)malloc(sizeof(char)*(strlen(request->host)+strlen(request->path)+2));
                
                if (!url) {
                    fprintf(stderr,"Invalid URL\n");
                    return NULL;
                }
                sprintf(url, "%s%s", request->host, request->path);

                struct cache_element* element =  handler->cache->find(url);

                if(element != NULL){
                    // return the element from here itself
                    handler->sendToSocket(element->data,socket,element->length, threadSsl);
                    shutdown(socket,SHUT_RDWR);     // No more receptions or transmissions
                    close(socket);

                    // free allocated memory 
                    ParsedRequest_destroy(request);
                    free(url);
                    free(buffer);
                    free(tempRequest);

                    handler->sem.release();
                    handler->sem.getValue(&p);
                    std::cout<<"Semaphore value is: "<<p<<std::endl;

                    // Gracefully exit function instead of abrupt exit(1)
                    return NULL;
                }
                
                // successfully parsed 
                memset(buffer,0,MAX_BYTES);
                if(!strcmp(request->method,"GET")){
                    // if get request 
                    if(request->host && request->path && (handler->checkHTTPversion(request->version) == 1)){
                        // handle request
                        // works fine
                        /*
                        std::cout<<request->headers->key<<"\n"
                                <<request->method<<"\n"
                                <<request->path<<"\n"
                                <<request->version<<"\n"
                                <<request->host<<"\n"
                                <<request->port<<"\n";
                        */ 
                        int res = handler->handleRequest(socket, request, url,handler->cache,threadSsl);
                        if(res == -1){
                            handler->log_stream->writeLogs(ipAddress,request->method,url,"MISS");
                            handler->sendErrorMessage(socket,404);
                        }
                        handler->log_stream->writeLogs(ipAddress,request->method,url,"HIT");
                    }else{
                        std::cout<<"some error occured"<<std::endl;
                        // close socket 
                        shutdown(socket,SHUT_RDWR);     // No more receptions or transmissions
                        close(socket);

                        // free allocated memory 
                        ParsedRequest_destroy(request);
                        free(url);
                        free(buffer);
                        free(tempRequest);

                        handler->sem.release();
                        handler->sem.getValue(&p);
                        std::cout<<"Semaphore value is: "<<p<<std::endl;

                        // Gracefully exit function instead of abrupt exit(1)
                        return NULL;
                    }
                }
                else{
                    std::cout<<"Other methods are not supported"<<std::endl;
                    ParsedRequest_destroy(request);
                    // close socket 
                    shutdown(socket,SHUT_RDWR);     // No more receptions or transmissions
                    close(socket);

                    // free allocated memory 
                    free(url);
                    free(buffer);
                    free(tempRequest);

                    handler->sem.release();
                    handler->sem.getValue(&p);
                    std::cout<<"Semaphore value is: "<<p<<std::endl;

                    // Gracefully exit function instead of abrupt exit(1)
                    return NULL;
                }
            }
        }
    } 
    else if(number_of_bytes_send_by_client < 0){
        std::cout<<"Error receiving client"<<std::endl;
    }
    else if(number_of_bytes_send_by_client == 0){
        std::cout<<"client disconnected"<<std::endl;

    }

    // close socket 
    shutdown(socket,SHUT_RDWR);     // No more receptions or transmissions
    close(socket);

    // free allocated memory 
    free(buffer);
    free(tempRequest);

    handler->sem.release();
    handler->sem.getValue(&p);
    std::cout<<"Semaphore value is: "<<p<<std::endl;

    // Gracefully exit function instead of abrupt exit(1)
    return NULL;
}

int main(int argc, char* argv[])
{
    handler->cache = new LRUCache(MAX_CACHE_SIZE, MAX_CACHE_ELEMENT_SIZE);   // initialize lru cache
    handler->sem.semaphore_init_(MAX_CLIENTS);    // initialize semaphore     
    pthread_mutex_init(&handler->cache->lock, NULL);    // initalize mutex 
    handler->log_stream = new IO_FileStream("./logs/log.txt");

    // check the command line arguments 
    if(argc < 2){
        fprintf(stderr,"Too few arguments\n");
        return 1;
    }
    const char* PORT = argv[1];   

    // 1. initialize ssl context, library
    ssl::initSSL();

    // 2. create ssl context 
    SSL_CTX* ctx = ssl::createSSLContext(cert,key);

    std::cout<<"[!] Setting Server SSL context for handler\n";
    Handler::setServerCTX(ctx);

    // create tcp sockets with bio
    BIO* acceptor_bio = BIO_new_accept(PORT);
    if(!acceptor_bio){
        ssl::reportErrors("Error creating acceptor BIO\n");
        SSL_CTX_free(ctx);
        return 1;
    }

    // 3. bind io with port and listen connections
    BIO_set_bind_mode(acceptor_bio, BIO_BIND_REUSEADDR);
    if(BIO_do_accept(acceptor_bio)<=0){
        ssl::reportErrors("Error creating acceptor BIO\n");
        SSL_CTX_free(ctx);
        return 1;
    }

    // creating socket
    int serverSocket;

    // return a file descriptor to server socket 
    if(BIO_get_fd(acceptor_bio, &serverSocket) == -1){
        ssl::reportErrors("BIO has failed to intialized");
        SSL_CTX_free(ctx);
        return 1;
    }

    // disabling nagles algorithm to bypass nagles delay
    int noDelayFlag = 1;
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

    std::cout<<"Server listening to port: "<<PORT<<"\n";

    int i = 0;                              // Iterator for thread_id (tid) and Accepted Client_Socket for each thread

    // 5. accept and handle clients
    while (true) {  
        BIO* clientBIO = nullptr;
        SSL* ssl = nullptr;

        // wait for client to connect to this server address
        if(BIO_do_accept(acceptor_bio) <= 0){
            ssl::reportErrors("Error accepting client connections");
            continue;
        }

        // when there is a client, pop client connection from bio chain
        // pop client socket
        clientBIO = BIO_pop(acceptor_bio);
        if(!clientBIO){
            ssl::reportErrors("Error accepting client connections");
            continue;
        }

        // define client socket internet address 
        struct sockaddr_storage clientAddress;
        socklen_t addrLen = sizeof(clientAddress);     // get the size of socket address structure 32 bit in size 
        memset(&clientAddress,0,sizeof(clientAddress));

        // accept connections
        int clientSocket ;
        if(BIO_get_fd(clientBIO, &clientSocket) == -1){
            ssl::reportErrors("[!] BIO has failed to intialized\n");
            continue; 
        }

        // get the IP address and port address client connected to  
        if(getpeername(clientSocket, (struct sockaddr*)&clientAddress, &addrLen) == -1){
            ssl::reportErrors("Error fetching name of peer socket\n");
            continue;
        }

        // convert ip address to string 
        char clientIPAddress[INET_ADDRSTRLEN];  // ipv4 address length string 
        int clientPort;
        struct sockaddr_in* internetAddress  = (struct sockaddr_in*)&clientAddress;
        inet_ntop(AF_INET, &internetAddress->sin_addr, clientIPAddress, INET_ADDRSTRLEN);
        clientPort = ntohs(internetAddress->sin_port);

        std::cout<<"Client connected to IP: "<<clientIPAddress<<" at port: "<<clientPort<<std::endl;
        std::cout << "[*] Accepted connection\n";

        // wrap ssl 
        // asscoiate a new ssl structure with new client
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

        // thread-specific arguments
        struct args* threadArgs = (struct args*)malloc(sizeof(struct args));
        threadArgs->connectedSocketId = clientSocket;
        threadArgs->ipAddress = (char*)malloc(INET_ADDRSTRLEN*sizeof(char));
        strcpy(threadArgs->ipAddress, clientIPAddress);
        threadArgs->ssl = ssl; 

        // create thread
        pthread_create(
            &handler->thread_ids[i],
            NULL,
            handleClient,              
            (void *)threadArgs
        );

        i++;
    }
    close(serverSocket);

    return 0;
}


/*
Linking c and c++ code 

gcc -c c_code.c -o c_code.o  # Compile C code
g++ -c cpp_code.cpp -o cpp_code.o  # Compile C++ code
g++ cpp_code.o c_code.o -o program  # Link both
./program  # Run the program

*/
// curl -x http://localhost:8080 http://www.google.com

// LAXMIBAISHIVHARE P%F-e2Z"P^ScAc^ (Niradhar)
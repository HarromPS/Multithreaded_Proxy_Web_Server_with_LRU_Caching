#ifndef LIBRARY // if not defined
#define LIBRARY

#include<fstream>
#include <mutex>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <thread>
#include <openssl/ssl.h>
#include "./proxy_parse.h"
#include "../library_functions/Semaphore.hpp"
#include "../library_functions/LRU_cache.hpp"
// #include "./ThreadPool.hpp"

class IO_FileStream{
private:
    std::fstream f_stream;
    std::string filePath;
    pthread_mutex_t lock;
public:
    IO_FileStream(const std::string& filepath);
    ~IO_FileStream();

    // writing the logging into a log file
    void writeLogs(const char* Ip_address,const char* method, const char* url,const char* cache_status);
};

// thread arguments 
typedef struct args{
    int connectedSocketId;
    char* ipAddress;
    int maxClients;
    SSL* ssl;  // each thread with its own ssl object 

    args(){}
    args(int maxClients): maxClients(maxClients){}
}args;

class Handler{
public:     
    int MAX_CLIENTS;
    int MAX_BYTES;
    int MAX_CACHE_ELEMENT_SIZE;
    int MAX_CACHE_SIZE;

    // LRU cache initialization 
    static SSL_CTX* serverCtx;
    LRUCache* cache;
    Semaphore sem;  // Define Semaphore to allow only max clients to access shared resource, shared resource is cache memory 
    std::vector<pthread_t> thread_ids;  // stores client thread ids
    IO_FileStream* log_stream;           // logging class to log request status
    // ThreadPool threads;

    Handler(int max_clients, int max_bytes, int max_cache_ele_size, int max_cache_size);
    ~Handler();

    static void setServerCTX(SSL_CTX* newServerCTX);
    int connectRemoteServer(const char* host_name, int serverPort, SSL** threadSSL);
    int handleRequest(int clientSocket, ParsedRequest* request, char* url,LRUCache* cache,SSL* threadSsl);
    int sendErrorMessage(int socket, int status_code);
    int checkHTTPversion(char *msg);
    void sendToSocket(const char* buffer, int socket, int buffer_length, SSL* threadSsl);
    void sendToSecureSocket(const char* buffer, int socket, int buffer_length, SSL* threadSsl);
    void sendFromServerToClientSocket(int serverSocket,int clientSocket,char* url,LRUCache* cache, SSL* clientSocketSSl,SSL* serverSocketSSl);
    void forwardInTunnel(int clientSocket,int serverSocket, SSL* clientSocketSSl,SSL* serverSocketSSl);
    void handleConnectMethod(std::string& request, int clientSocket, IO_FileStream* log_stream, SSL*clientThreadSsl);
};

#endif
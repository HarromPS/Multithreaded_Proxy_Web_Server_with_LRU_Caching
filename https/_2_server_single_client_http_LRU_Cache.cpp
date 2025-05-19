// C++ program to show the example of server application in
// socket programming
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <map>
#include <thread>
#include "./headers/proxy_utils.h"
#include "./headers/proxy_parse.h"
#include "./library_functions/Semaphore.cpp"
#include "./library_functions/LRU_cache.cpp"

#define MAX_CLIENTS 10
#define MAX_BYTES 100    // max allowed size of request/response
#define _1K (1<<10)          // 1k i.e 1024
#define MAX_CACHE_ELEMENT_SIZE (30*_1K) // 30K
#define MAX_CACHE_SIZE (200*_1K) // 200K

// LRU cache initialization 
LRUCache* cache;
Semaphore sem;  // Define Semaphore to allow only max clients to access shared resource, shared resource is cache memory 
pthread_t thread_ids[MAX_CLIENTS];  // stores client thread ids
IO_FileStream* log_stream;           // logging class to log request status

// thread arguments 
struct args{
    int connectedSocketId;
    char* ipAddress;
    int maxClients;

    args(){}
    args(int maxClients): maxClients(maxClients){}
};

int connectRemoteServer(const char* host_name, int serverPort){
    int remoteServerSocket = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if(remoteServerSocket < 0){
        fprintf(stderr, "Error in creating socket\n");
        return -1;
    }

    // perform DNS resolution and find ip address using host/domain name 
    struct hostent *host = gethostbyname(host_name);
    if(host == NULL){
        fprintf(stderr, "no such host exist\n");
        return -1;
    }

    // define server address
    struct sockaddr_in serverAddress;
    memset((struct sockeadd_in*)&serverAddress, 0, sizeof (struct sockaddr));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(serverPort); // host port to network port address

    // copy address of host into server ip address
    bcopy((char*)host->h_addr,(char*)&serverAddress.sin_addr.s_addr,host->h_length);

    // connect to remote server 
    int conn = connect(remoteServerSocket, (struct sockaddr*)&serverAddress, (socklen_t)sizeof(serverAddress));
    if(conn < 0){
        fprintf(stderr,"error in connecting remote server\n");
        return -1;
    }

    // free(host);          // free(): invalid pointer, attempting to free something that isn't a pointer to a "freeable" memory address
    return remoteServerSocket;  // return remoteserver socket reference
}

void sendToSocket(const char* buffer, int socket, int buffer_length){
    int total_send=0;

    while(total_send < buffer_length){
        int send_bytes = send(socket, (void*)(buffer + total_send), buffer_length - total_send ,0);
        if(send_bytes < 0){
            fprintf(stderr,"error sending to client");
            return ;
        }
        total_send+=send_bytes;
    }

}

void sendFromServerToClientSocket(int serverSocket,int clientSocket,char* url){
    int MAX_BUFFER = MAX_BYTES;
    char* buffer = (char*)malloc(MAX_BUFFER*sizeof(char));
    char* tempData = (char*)malloc(MAX_BUFFER*sizeof(char));
    tempData[0]='\0';               // empty string initially

    int totalReceived=0;

    // receive from server and send to client 
    int bytes_received_from_server = recv(serverSocket, buffer, MAX_BUFFER, 0);
    if(bytes_received_from_server < 0){
        fprintf(stderr,"Error receiving data from client\n");
        shutdown(serverSocket, SHUT_RDWR);
        shutdown(clientSocket, SHUT_RDWR);
        free(buffer);
        free(tempData);
        return;
    }
    else if(bytes_received_from_server == 0){
        fprintf(stderr,"Connection Closed\n");
        shutdown(serverSocket, SHUT_RDWR);
        shutdown(clientSocket, SHUT_RDWR);
        free(buffer);
        free(tempData);
        return;
    }

    while(bytes_received_from_server > 0){
        // send to client
        sendToSocket(buffer, clientSocket, bytes_received_from_server);

        // make a copy of data
       
        if(totalReceived + bytes_received_from_server >= MAX_BUFFER){
            // increase size of buffer and reallocate additional memory for tempData
            MAX_BUFFER += bytes_received_from_server;
            tempData = (char*)realloc(tempData, MAX_BUFFER*sizeof(char));
            buffer = (char*)realloc(buffer, MAX_BUFFER*sizeof(char));
        }
        // strcat(tempData, buffer);    // both strings needs to be null terminated 

        memcpy(tempData+totalReceived, buffer,bytes_received_from_server);
        totalReceived+=bytes_received_from_server;

        // empty buffer 
        memset(buffer,0,MAX_BUFFER); 
        bytes_received_from_server = recv(serverSocket, buffer,MAX_BUFFER,0);  
    }

    if(bytes_received_from_server<0){
        fprintf(stderr, "Error while receiving from server");
    }

    cache->addElementToCache((char*)tempData,totalReceived,url);   // 1 for null terminator
    cache->printList();
    
    free(buffer);
    free(tempData);

    // add the data to cache 

    // for(long unsigned int i=0;i<strlen(url);i++){
    //     std::cout<<url[i];
    // }
    // std::cout<<std::endl;


}

int handleRequest(int clientSocket, ParsedRequest* request, char* url){
    // handle to get request to the original server for now, after that we will see to implement lru cache 
    // modify headers 
    
    int res = ParsedHeader_set(request,"Proxy-Connection","close");   // connection close after response
    if(res<0){
        fprintf(stderr,"cannot set header with key: Connection; value:close;" );
        return -1;
    }

    res = ParsedHeader_set(request,"Connection","close");   // connection close after response
    if(res<0){
        fprintf(stderr,"cannot set header with key: Connection; value:close;" );
        return -1;
    }


    // IMPLEMENT Anonymity: by striping out sensitive headers
    /*
        X-Forwarded-For:	Client's original IP address 
        Via:	            shows request through proxy 
        Forwarded:	        RFC-standard way to expose proxy info
        User-Agent:	        Client browser/system info 
        Referer:	        Last URL — for tracking purpose
        Cookie:	            Sometimes leaks identity 
    */

    res = ParsedHeader_set(request,"X-Forwarded-For","");
    if(res<0){
        fprintf(stderr,"cannot set header with key: X-Forwarded-For; value:null;" );
        return -1;
    }

    res = ParsedHeader_set(request,"Via","");
    if(res<0){
        fprintf(stderr,"cannot set header with key: Via; value:null;" );
        return -1;
    }

    res = ParsedHeader_set(request,"Forwarded","by=Anonymous;for=You;host=test.com;proto=http");
    if(res<0){
        fprintf(stderr,"cannot set header with key: Forwarded; value:null;" );
        return -1;
    }

    res = ParsedHeader_set(request,"User-Agent","AnonymousProxy/1.0");
    if(res<0){
        fprintf(stderr,"cannot set header with key: User-Agent; value:AnonymousProxy/1.0;" );
        return -1;
    }

    res = ParsedHeader_set(request,"Referer","http://test.com");
    if(res<0){
        fprintf(stderr,"cannot set header with key: Referer; value:http://test.com;" );
        return -1;
    }

    // check if host available 
    void* hostVal = ParsedHeader_get(request,"Host");
    if(hostVal == NULL){
        // if not set, set headers 
        if(ParsedHeader_set(request,"Host",request->host) < 0){
            fprintf(stderr,"cannot set header with key: Host; value:val;" );
            return -1;
        }
    }

    int header_length = ParsedHeader_headersLen(request);
    char* header_buffer = (char*)calloc(sizeof(char),(header_length+1));    // +1 for null character 
    header_buffer[0]='\0';

    // now convert to a raw http request string from struct into buffer
    if(ParsedRequest_unparse_headers(request,header_buffer,header_length)<0){
        fprintf(stderr,"unparse failed" );
        return -1;
    }   
    // strcat(header_buffer, "\r\n");
    // header_length = ParsedHeader_headersLen(request);
            
    header_buffer[header_length] = '\0';        // needed to end this header as it is a string for now 

    // header length and header buffer length checks
    if (header_buffer == NULL || strlen(header_buffer) != (long unsigned int)header_length) {
        fprintf(stderr, "Error: header_buffer is invalid\n");
        return -1;
    }

    // allocate a buffer to make a new GET request to the original server 
    // extract the get request to original server by removing details to this proxy server 
    // and making a new get request to original server 
    int requestSize = strlen(request->method) + strlen(request->path) + strlen(request->version) + header_length + 4 ;  

    if (request->method == NULL || request->path == NULL || request->version == NULL || header_buffer == NULL) {
        fprintf(stderr, "Error: One or more strings are NULL\n");
        return -1;
    }
    
    // Verify null termination (optional but helpful for debugging)
    // printf("Method: %s (len=%zu)\n", request->method, strlen(request->method));
    // printf("Path: %s (len=%zu)\n", request->path, strlen(request->path));
    // printf("Version: %s (len=%zu)\n", request->version, strlen(request->version));
    // printf("Headers: %s (len=%zu)\n", header_buffer, strlen(header_buffer));
    // printf("request size: %d\n", requestSize-header_length);

    // original server request 
    char* serverRequest = (char*)malloc((requestSize+1)*sizeof(char));

    // construct a HTTP request 
    // serverRequest[0]='\0';                      // start as an empty string
    // strcpy(serverRequest, request->method);              // method
    // strcat(serverRequest, " "); 
    // strcat(serverRequest, request->path);       // pathname 
    // strcat(serverRequest, " ");
    // strcat(serverRequest, request->version);    // http version 
    // strcat(serverRequest, "\r\n");              // http termination sequence
    // strcat(serverRequest, header_buffer);       // headers 

    // snprintf prevents buffer overflow
    snprintf(serverRequest, requestSize+1, "%s %s %s\r\n%s",
            request->method,
            request->path,
            request->version,
            header_buffer
    );  

    /*
        GET /index.html HTTP/1.1\r\n
        Host: www.example.com\r\n
        Connection: close\r\n               
        User-Agent: Mozilla/5.0\r\n
        \r\n
    */

    // Now, Create a connection with remote server 
    int serverPort = 80;                        // http default server port
    if(request->port){
        // if client provided a specific port 
        serverPort = atoi(request->port);
    }

    int remoteServerSocket = connectRemoteServer(request->host, serverPort);
    if(remoteServerSocket < 0){
        fprintf(stderr,"error connecting to remote server");
        return -1;
    }

    // send request to remote server 
    sendToSocket(serverRequest, remoteServerSocket, requestSize);

    // std::cout<<"Data requested"<<std::endl;

    // send data from remote server to client 
    sendFromServerToClientSocket(remoteServerSocket, clientSocket, url);
    
    // shoutdown 
    shutdown(remoteServerSocket,SHUT_RDWR);
    shutdown(clientSocket,SHUT_RDWR);
    free(header_buffer);
    free(serverRequest);
    return 0;

    // get the length of buffer i.e number of characters before null character 
    // size_t http_request_buffer_length = strlen(buffer);
}

void forwardInTunnel(int clientSocket,int serverSocket){
    // using select method, to handle multiple socket connections without multithreading 

    // create set of file descriptors
    fd_set fds;                 // select will monitor these descriptors
    char buffer[4096];          // temporary storage for received data
    int pos=0;

    // client and server talking to each other over tcp connection 
    while(true){
        FD_ZERO(&fds);          // clears the fd set 
        FD_SET(clientSocket, &fds); // add both client and remote sockets to be monitored
        FD_SET(serverSocket, &fds); // add both client and remote sockets to be monitored

        // needed max fds to scan 
        int max_fd = (clientSocket > serverSocket) ? clientSocket:serverSocket;

        // wait for activity(hand raise) i.e monitor 
        int activity = select(max_fd+1, &fds, NULL, NULL, NULL);
        if(activity<0){
            fprintf(stderr,"Something went wrong\n");
            break;
        }

        // from client to remote
        // client sends the data(client raised hand) to send data
        if(FD_ISSET(clientSocket, &fds)){
            int bytesReceived = recv(clientSocket, buffer, sizeof(buffer),0);
            if(bytesReceived<=0){
                fprintf(stderr,"Unable to receive data from client\n");
                break;
            }
            // send data to server 
            send(serverSocket, buffer, bytesReceived, 0);   // send data received from client to the server 
        }

        // if server sends data to client then same 
        if(FD_ISSET(serverSocket, &fds)){
            int bytesReceived = recv(serverSocket, buffer, sizeof(buffer),0);
            if(bytesReceived<=0){
                fprintf(stderr,"Unable to receive data from server\n");
                break;
            }
            // send data to server(encrypted which cant be read by the proxy server)
            send(clientSocket, buffer, bytesReceived, 0);   // send data received from client to the server 
            for(int i=pos;i<bytesReceived;i++){
                std::cout<<buffer[i];
            }
            pos+=bytesReceived;
        }

    }

    // finally close the connection when any one is closed 
    close(clientSocket);
    close(serverSocket);
}

void handleConnectMethod(std::string& request, int clientSocket){
    // parse host name and port number
    std::string host_port,host;
    // get the request line 
    std::string requestLine;
    int i=0;
    while(request[i]!='\r'){
        requestLine+=request[i];
        i++;
    }
    
    // skip first 8 characters CONNECT_, then get host until :
    i=8;
    while(requestLine[i]!=':'){
        host+=requestLine[i];
        i++;
    }

    i+=1;
    // get the port number
    while(requestLine[i]!=' '){
        host_port+=requestLine[i];
        i++;
    }

    int port = std::stoi(host_port);        // convert string port to integer port

    // connect to target server 
    int remoteSocket = connectRemoteServer(host.c_str(),port);
    if(remoteSocket < 0){
        fprintf(stderr,"error connecting to remote server");
        return;
    }

    // get the ip address of the host and log 
    struct hostent* host_entry = gethostbyname(host.c_str());
    if(host_entry == NULL){
        fprintf(stderr, "no such host exist\n");
        log_stream->writeLogs("",request.substr(0,7).c_str(),host.c_str(),"MISS");
        return;
    }
    std::string ipAddress;
    
    for (int i = 0; host_entry->h_addr_list[i] != nullptr; ++i) {
        in_addr addr;
        memcpy(&addr, host_entry->h_addr_list[i], host_entry->h_length);
        ipAddress += inet_ntoa(addr);
        if(host_entry->h_addr_list[i+1] != nullptr)
        ipAddress += ",";
    }
    log_stream->writeLogs(ipAddress.c_str(),request.substr(0,7).c_str(),host.c_str(),"HIT");

    // say 200 ok as acknowledgement, then start complete handshake
    std::string ack = "HTTP/1.1 200 CONNECTION ESTABLISHED\r\n\r\n";
    send(clientSocket,ack.c_str(),ack.length(),0);

    // now let the client and server talk each other until tunnel is closed
    forwardInTunnel(clientSocket, remoteSocket);

    close(remoteSocket);
}

void* handleClient(void* arguments)
{
    // acquire semaphore
    sem.acquire();
    int p;
    sem.getValue(&p);
    std::cout<<"semaphore value is:"<<p<<std::endl;

    struct args *args = (struct args *)arguments;
    char* ipAddress = args->ipAddress;
    int socket = args->connectedSocketId;  // create a copy of client socket file descriptor 
    // delete (int*)args;           // double or free corruption error

    int number_of_bytes_send_by_client=0, total_received_bytes_from_client=0;
    std::cout << "Thread started for socket: " << socket << std::endl;

    // create a buffer of max bytes of type char 
    int MAX_BUFFER = MAX_BYTES;
    char* buffer = (char*)calloc(MAX_BUFFER,sizeof(char));
    memset(buffer, 0, MAX_BUFFER);
    number_of_bytes_send_by_client = recv(socket, buffer, MAX_BUFFER,0);       // receive client data 
    
    // check for recv return value and handle that properly
    if(number_of_bytes_send_by_client < 0){
        fprintf(stderr,"Error receiving data from client\n");
        shutdown(socket, SHUT_RDWR);
        free(buffer);
        sem.release();
        sem.getValue(&p);
        std::cout<<"Semaphore value is: "<<p<<std::endl;
        return NULL;
    }
    else if(number_of_bytes_send_by_client == 0){
        fprintf(stderr,"Connection Closed\n");
        shutdown(socket, SHUT_RDWR);
        free(buffer);
        sem.release();
        sem.getValue(&p);
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
                sem.release();
                sem.getValue(&p);
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
            number_of_bytes_send_by_client = recv(socket, buffer+total_received_bytes_from_client,MAX_BUFFER-total_received_bytes_from_client,0);

            // error handling while receiving data from client
            if(number_of_bytes_send_by_client < 0){
                fprintf(stderr,"Error receiving data from client\n");
                shutdown(socket, SHUT_RDWR);
                free(buffer);
                sem.release();
                sem.getValue(&p);
                std::cout<<"Semaphore value is: "<<p<<std::endl;
                return NULL;
            }
            else if(number_of_bytes_send_by_client == 0){
                fprintf(stderr,"Connection Closed\n");
                shutdown(socket, SHUT_RDWR);
                free(buffer);
                sem.release();
                sem.getValue(&p);
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
    for(int i=0;i<bufferLength;i++){
        tempRequest[i]=buffer[i];
    }
    
    // for(int i=0;i<bufferLength;i++){
    //     std::cout<<tempRequest[i];
    // }
    // std::cout<<std::endl;

    tempRequest[bufferLength]='\0'; // add null terminator character

    // check if there is request from client 
    if(number_of_bytes_send_by_client > 0){
        total_received_bytes_from_client = strlen(buffer);

        // check if this is a CONNECT METHOD
        std::string req(buffer, bufferLength);
        std::cout<<req<<std::endl;

        if(req.find("CONNECT") == 0){
            // handle connect requests
            handleConnectMethod(req, socket);
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

                sem.release();
                sem.getValue(&p);
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

                struct cache_element* element =  cache->find(url);

                if(element != NULL){
                    // return the element from here itself
                    sendToSocket(element->data,socket,element->length);
                    shutdown(socket,SHUT_RDWR);     // No more receptions or transmissions
                    close(socket);

                    // free allocated memory 
                    ParsedRequest_destroy(request);
                    free(url);
                    free(buffer);
                    free(tempRequest);

                    sem.release();
                    sem.getValue(&p);
                    std::cout<<"Semaphore value is: "<<p<<std::endl;

                    // Gracefully exit function instead of abrupt exit(1)
                    return NULL;
                }
                
                // successfully parsed 
                memset(buffer,0,MAX_BYTES);
                if(!strcmp(request->method,"GET")){
                    // if get request 
                    if(request->host && request->path && (checkHTTPversion(request->version) == 1)){
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
                        int res = handleRequest(socket, request, url);
                        if(res == -1){
                            log_stream->writeLogs(ipAddress,request->method,url,"MISS");
                            sendErrorMessage(socket,404);
                        }
                        log_stream->writeLogs(ipAddress,request->method,url,"HIT");
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

                        sem.release();
                        sem.getValue(&p);
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

                    sem.release();
                    sem.getValue(&p);
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

    sem.release();
    sem.getValue(&p);
    std::cout<<"Semaphore value is: "<<p<<std::endl;

    // Gracefully exit function instead of abrupt exit(1)
    return NULL;
}

int main(int argc, char* argv[])
{
    cache = new LRUCache(MAX_CACHE_SIZE, MAX_CACHE_ELEMENT_SIZE);   // initialize lru cache
    sem.semaphore_init_(MAX_CLIENTS);    // initialize semaphore     
    pthread_mutex_init(&lock, NULL);    // initalize mutex 
    log_stream = new IO_FileStream("./logs/log.txt");

    // check the command line arguments 
    int PORT=8080;
    if(argc < 2){
        fprintf(stderr,"Too few arguments\n");
        return 1;
    }
    else{
        PORT = atoi(argv[1]);
    }

    // creating socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0); // domain ipv4, tcp type, protocol
    if(serverSocket == -1){
        fprintf(stderr,"server socket creation failed\n");
        return 1;
    }

    // allow reuse of same socket address 
    int reuse = 1;
    int opt = setsockopt(
        serverSocket,
        SOL_SOCKET,
        SO_REUSEADDR,
        (const char*)&reuse,
        sizeof(reuse)
    );
    if(opt < 0){
        std::cout<<"setsockoption(SO_REUSEADDR) failed\n";
        return 0;
    }

    // specifying the address
    sockaddr_in serverAddress;                  //  data type that is used to store the address of the socket.
    memset(&serverAddress,0,sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;         // ipv4 protocol family
    serverAddress.sin_port = htons(PORT);       // used to convert the unsigned int from machine byte order to network byte order
    serverAddress.sin_addr.s_addr = INADDR_ANY; // listen all ips

    // binding socket.
    if(bind(
        serverSocket, 
        (struct sockaddr *)&serverAddress, 
        sizeof(serverAddress)) < 0){
            fprintf(stderr,"Binding failed\n");
            return 1;
    }

    // listening to the assigned socket
    if(listen(serverSocket, 5) < 0){
        fprintf(stderr,"Listen failed\n");
        return 1;
    }
    std::cout<<"Server listening to port: "<<PORT<<"\n";

    int i = 0;                              // Iterator for thread_id (tid) and Accepted Client_Socket for each thread
	struct args arg[MAX_CLIENTS];    // This array stores socket descriptors of connected clients 

    while (true) {  
        // define client socket internet address 
        struct sockaddr_in clientAddress;
        memset(&clientAddress,0,sizeof(clientAddress));

        // accept connections
        // accept is a blocking system call 
        int clientLength = sizeof(struct sockaddr);
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, (socklen_t*)&clientLength);   // client file descriptor

        if (clientSocket < 0) {
            fprintf(stderr,"[!] Accept failed\n");
            break;
        }
        
        // get the IP address and port address client connected to  
        struct sockaddr_in* clientPtr = (struct sockaddr_in*)&clientAddress;    // create copy of client address 
        struct in_addr ip_addr = clientPtr->sin_addr;   // ip address

        // convert ip address to string 
        char straddr[INET_ADDRSTRLEN];  // ipv4 address length string 
        inet_ntop(
            AF_INET,    // ipv4
            &ip_addr,   // internet ip address
            straddr,    // string ip address
            INET_ADDRSTRLEN // address length
        );

        std::cout<<"Client address: "<<straddr<<" Client port: "<<(ntohs(clientAddress.sin_port))<<std::endl;
        
        std::cout << "[*] Accepted connection\n";

        // int pid = fork();
        // if(pid == 0){
        //     handleClient((void*)&clientSocket);     // child process running in background
        //     std::cout<<"Client connection closed successfully\n";
        //     close(clientSocket);
        //     _exit(0);
        // }else{
        //     close(clientSocket);                    // parent process
        // }

        // WORKING CODE BELOW, ABOVE CODE IS FOR ONLY 1 REQUEST 
        // handleClient((void*)&clientSocket);     // child process running in background
        // std::cout<<"Client connection closed successfully\n";
        // close(clientSocket);
        // _exit(0);

        arg[i].connectedSocketId = clientSocket;
        arg[i].ipAddress = (char*)malloc(INET_ADDRSTRLEN*sizeof(char));
        strcpy(arg[i].ipAddress,straddr);

        // create thread
        pthread_create(
            &thread_ids[i],
            NULL,
            handleClient,                       // return value is a void* 
            (void *)&arg[i]
        );

        i++;
    }
    
    for(int j=0;j<i;j++){
        free(arg[i].ipAddress);
    }

    // closing the socket.
    delete cache;
    delete log_stream;
    
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
#include<iostream>
#include<time.h>
#include<fstream>
#include<cstdio>
#include <mutex>
#include<ctime>
#include<cstring>
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
#include <openssl/err.h>
#include "../headers/proxy_utils.hpp"
#include "../headers/ssl_library.hpp"
#include "../library_functions/Semaphore.hpp"       // do not include .cpp files directly to avoid multiple defination error
#include "../library_functions/LRU_cache.hpp"

#define cert "../files/server.pem"

// LOG FILE LIBRARY FUNCTION DEFINATIONS
// define definations for filestream methods
// constructor 
IO_FileStream::IO_FileStream(const std::string& filepath){
	f_stream.open(filepath, std::ios::app);	// open in append mode
	if(!f_stream.is_open()){
		fprintf(stderr,"Unable to open log file\n");
	}
}

// destructor 
IO_FileStream::~IO_FileStream(){
	// close the file stream 
	f_stream.close();
	pthread_mutex_destroy(&lock);
}

void IO_FileStream::writeLogs(const char* Ip_address,const char* method,const char* url, const char* cache_status){
	std::time_t timestamp;          // timestamp data structrure 
    std::time(&timestamp);          // time function, returns timestamp value into memory addr provided

	struct tm datetime = *localtime(&timestamp);	// datatime structure with each component
	char output[50];
	strftime(output, sizeof(output), "%Y-%d-%e %I:%M:%S %p", &datetime);	// format date time string 

	// this is the critical section to write into the log file
	int mutex_lock = pthread_mutex_lock(&lock);	// lock acquired
	if(mutex_lock != 0){
		std::cerr << "Failed to acquire lock: " << std::endl;
		return;
	}
	std::cout<<"\nlock acquired to write logs "<<std::endl;

	// check if file stream is associated with the file and file stream object 
    if(f_stream.is_open()){
        // move to the end position 
        f_stream.seekp(std::ofstream::end);

        // write timestamp to the file
		// [%04d-%02d-%02d %02d:%02d:%02d] IP: %s | Method: %s | URL: %s | Cache: %s\n
		int logLength = strlen(Ip_address) + strlen(method) + strlen(url) + strlen(cache_status) + 100;
		char* log = (char*)malloc(logLength*sizeof(char));	

		snprintf(log, logLength, "[%s] | IP: %s | Method: %s | URL: %s | Cache Status: %s\n",
            output,
			Ip_address,
			method,
			url,
			cache_status
    	);  

		// size_t logsize = strlen(log);
		// for(size_t i=0;i<logsize;i++){
		// 	std::cout<<log[i];
		// }
		// std::cout<<cache_status<<std::endl;

        f_stream << log;
		f_stream.flush();	// release stream buffer 

		// free the allocated memory
		free(log);
    }
	mutex_lock = pthread_mutex_unlock(&lock);
	std::cout<<"\nlock released to write logs "<<std::endl;
}

// HANDLER FUNCTIONS

// constructor
Handler::Handler(int max_clients, int max_bytes, int max_cache_ele_size, int max_cache_size): MAX_CLIENTS(max_clients), MAX_BYTES(max_bytes), MAX_CACHE_ELEMENT_SIZE(max_cache_ele_size), MAX_CACHE_SIZE(max_cache_size){
	thread_ids.resize(max_clients);
}

// destructor
Handler::~Handler(){
	delete cache;
	delete log_stream;
}

int Handler::checkHTTPversion(char *msg){
	int version = -1;
	if(strncmp(msg, "HTTP/1.1", 8) == 0){
		version = 1;
	}
	else if(strncmp(msg, "HTTP/1.0", 8) == 0){
		version = 1;										// Handling this similar to version 1.1
	}

	return version;
}

int Handler::sendErrorMessage(int socket, int status_code)
{
	char str[1024];
	char currentTime[50];
	time_t now = time(0);

	struct tm data = *gmtime(&now);
	strftime(currentTime,sizeof(currentTime),"%a, %d %b %Y %H:%M:%S %Z", &data);
    int send_data=0;

	switch(status_code)
	{   
        // snprintf writes formatted output into the str buffer, to send buffer to client
		case 400: snprintf(str, sizeof(str), "HTTP/1.1 400 Bad Request\r\nContent-Length: 95\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>400 Bad Request</TITLE></HEAD>\n<BODY><H1>400 Bad Rqeuest</H1>\n</BODY></HTML>", currentTime);
				  printf("400 Bad Request\n");
				  send_data = send(socket, str, strlen(str)+1, 0);
                  if(send_data < 0){
                    fprintf(stderr,"Error sending data\n");
                    break;
                  }
                  send_data=0;
				  break;

		case 403: snprintf(str, sizeof(str), "HTTP/1.1 403 Forbidden\r\nContent-Length: 112\r\nContent-Type: text/html\r\nConnection: keep-alive\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>403 Forbidden</TITLE></HEAD>\n<BODY><H1>403 Forbidden</H1><br>Permission Denied\n</BODY></HTML>", currentTime);
				  printf("403 Forbidden\n");
				  send(socket, str, strlen(str)+1, 0);
                  if(send_data < 0){
                    fprintf(stderr,"Error sending data\n");
                    break;
                  }
                  send_data=0;
				  break;

		case 404: snprintf(str, sizeof(str), "HTTP/1.1 404 Not Found\r\nContent-Length: 91\r\nContent-Type: text/html\r\nConnection: keep-alive\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD>\n<BODY><H1>404 Not Found</H1>\n</BODY></HTML>", currentTime);
				  printf("404 Not Found\n");
				  send(socket, str, strlen(str)+1, 0);
                  if(send_data < 0){
                    fprintf(stderr,"Error sending data\n");
                    break;
                  }
                  send_data=0;
				  break;

		case 500: snprintf(str, sizeof(str), "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 115\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>500 Internal Server Error</TITLE></HEAD>\n<BODY><H1>500 Internal Server Error</H1>\n</BODY></HTML>", currentTime);
				  printf("500 Internal Server Error\n");
				  send(socket, str, strlen(str)+1, 0);
                  if(send_data < 0){
                    fprintf(stderr,"Error sending data\n");
                    break;
                  }
                  send_data=0;
				  break;

		case 501: snprintf(str, sizeof(str), "HTTP/1.1 501 Not Implemented\r\nContent-Length: 103\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>404 Not Implemented</TITLE></HEAD>\n<BODY><H1>501 Not Implemented</H1>\n</BODY></HTML>", currentTime);
				  printf("501 Not Implemented\n");
				  send(socket, str, strlen(str)+1, 0);
                  if(send_data < 0){
                    fprintf(stderr,"Error sending data\n");
                    break;
                  }
                  send_data=0;
				  break;

		case 505: snprintf(str, sizeof(str), "HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: 125\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>505 HTTP Version Not Supported</TITLE></HEAD>\n<BODY><H1>505 HTTP Version Not Supported</H1>\n</BODY></HTML>", currentTime);
				  printf("505 HTTP Version Not Supported\n");
				  send(socket, str, strlen(str)+1, 0);
                  if(send_data < 0){
                    fprintf(stderr,"Error sending data\n");
                    break;
                  }
                  send_data=0;
				  break;

		default:  return -1;

	}
	return 1;
}

int Handler::connectRemoteServer(const char* host_name, int serverPort,SSL** threadSsl){
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

    // For HTTPS connections, set up SSL
    if (serverPort == 443) {
        // Setup SSL for remote server
        SSL_CTX* sslClientCtx = SSL_CTX_new(TLS_client_method());
        SSL* remoteSsl = SSL_new(sslClientCtx);
        if (!remoteSsl) {
            fprintf(stderr, "Failed to create new SSL structure\n");
            close(remoteServerSocket);
            return -1;
        }

        SSL_set_fd(remoteSsl, remoteServerSocket);

        if (SSL_connect(remoteSsl) <= 0) {
            fprintf(stderr, "SSL_connect failed\n");
            ERR_print_errors_fp(stderr);
            SSL_free(remoteSsl);
            close(remoteServerSocket);
            return -1;
        }

        // Set the pointer back to caller - critical fix here
        *threadSsl = remoteSsl;
        
        fprintf(stdout, "SSL connection established with remote server\n");
    }

    // free(host);          // free(): invalid pointer, attempting to free something that isn't a pointer to a "freeable" memory address
    return remoteServerSocket;  // return remoteserver socket reference
}

void Handler::sendToSocket(const char* buffer, int socket, int buffer_length, SSL* threadSsl){
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

void Handler::sendToSecureSocket(const char* buffer, int socket, int buffer_length, SSL* threadSsl){
    int total_send=0;

    while(total_send < buffer_length){
        int send_bytes = SSL_write(threadSsl, (void*)(buffer + total_send), buffer_length - total_send);
        if(send_bytes < 0){
            fprintf(stderr,"error sending to client");
            return ;
        }
        total_send+=send_bytes;
    }
}

void Handler::sendFromServerToClientSocket(int serverSocket,int clientSocket,char* url,LRUCache* cache, SSL* clientSocketSSl,SSL* serverSocketSSl){
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
        sendToSecureSocket(buffer, clientSocket, bytes_received_from_server,clientSocketSSl);

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

int Handler::handleRequest(int clientSocket, ParsedRequest* request, char* url,LRUCache* cache,SSL* threadSsl){
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

    SSL* remoteSSL = nullptr;
    int remoteServerSocket = connectRemoteServer(request->host, serverPort,&remoteSSL);
    if(remoteServerSocket < 0){
        fprintf(stderr,"error connecting to remote server");
        return -1;
    }

    // send request to remote server 
    sendToSocket(serverRequest, remoteServerSocket, requestSize,remoteSSL);

    // std::cout<<"Data requested"<<std::endl;

    // send data from remote server to client 
    sendFromServerToClientSocket(remoteServerSocket, clientSocket, url, cache,threadSsl,remoteSSL);
    
    // shoutdown 
    shutdown(remoteServerSocket,SHUT_RDWR);
    shutdown(clientSocket,SHUT_RDWR);
    free(header_buffer);
    free(serverRequest);
    return 0;

    // get the length of buffer i.e number of characters before null character 
    // size_t http_request_buffer_length = strlen(buffer);
}

void Handler::forwardInTunnel(int clientSocket, int serverSocket, SSL* clientSocketSSL, SSL* serverSocketSSL) {
    fd_set readfds;
    char buffer[4096];
    struct timeval tv;
    
    while (true) {
        FD_ZERO(&readfds);
        FD_SET(clientSocket, &readfds);
        FD_SET(serverSocket, &readfds);

        int max_fd = (clientSocket > serverSocket) ? clientSocket : serverSocket;
        
        // Set a timeout to prevent infinite blocking
        tv.tv_sec = 30;  // 30 seconds timeout
        tv.tv_usec = 0;

        int activity = select(max_fd + 1, &readfds, NULL, NULL, &tv);
        if (activity < 0) {
            fprintf(stderr, "Select error: %s\n", strerror(errno));
            break;
        }
        
        // Timeout occurred
        if (activity == 0) {
            fprintf(stderr, "Tunnel timeout - no activity for 30 seconds\n");
            break;
        }

        // Client → Server data flow
        if (FD_ISSET(clientSocket, &readfds)) {
            int bytesReceived;
            
            // Read data from client
            if (clientSocketSSL) {
                bytesReceived = SSL_read(clientSocketSSL, buffer, sizeof(buffer));
                if (bytesReceived <= 0) {
                    int ssl_err = SSL_get_error(clientSocketSSL, bytesReceived);
                    if (ssl_err == SSL_ERROR_ZERO_RETURN) {
                        fprintf(stderr, "Client closed SSL connection\n");
                    } else {
                        fprintf(stderr, "SSL_read error from client: %d\n", ssl_err);
                        ERR_print_errors_fp(stderr);
                    }
                    break;
                }
            } else {
                bytesReceived = SSL_read(clientSocketSSL, buffer, sizeof(buffer));
                if (bytesReceived <= 0) {
                    if (bytesReceived == 0) {
                        fprintf(stderr, "Client disconnected\n");
                    } else {
                        fprintf(stderr, "Recv error from client: %s\n", strerror(errno));
                    }
                    break;
                }
            }
            
            // Write data to server
            int bytesSent;
            if (serverSocketSSL) {
                bytesSent = SSL_write(serverSocketSSL, buffer, bytesReceived);
                if (bytesSent <= 0) {
                    fprintf(stderr, "SSL_write error to server: %d\n", 
                             SSL_get_error(serverSocketSSL, bytesSent));
                    ERR_print_errors_fp(stderr);
                    break;
                }
            } else {
                bytesSent = send(serverSocket, buffer, bytesReceived, 0);
                if (bytesSent <= 0) {
                    fprintf(stderr, "Send error to server: %s\n", strerror(errno));
                    break;
                }
            }
        }

        // Server → Client data flow
        if (FD_ISSET(serverSocket, &readfds)) {
            int bytesReceived;
            
            // Read data from server
            if (serverSocketSSL) {
                bytesReceived = SSL_read(serverSocketSSL, buffer, sizeof(buffer));
                if (bytesReceived <= 0) {
                    int ssl_err = SSL_get_error(serverSocketSSL, bytesReceived);
                    if (ssl_err == SSL_ERROR_ZERO_RETURN) {
                        fprintf(stderr, "Server closed SSL connection\n");
                    } else {
                        fprintf(stderr, "SSL_read error from server: %d\n", ssl_err);
                        ERR_print_errors_fp(stderr);
                    }
                    break;
                }
            } else {
                bytesReceived = recv(serverSocket, buffer, sizeof(buffer), 0);
                if (bytesReceived <= 0) {
                    if (bytesReceived == 0) {
                        fprintf(stderr, "Server disconnected\n");
                    } else {
                        fprintf(stderr, "Recv error from server: %s\n", strerror(errno));
                    }
                    break;
                }
            }
            
            // Print received data to terminal (for debugging)
            printf("Sending to client: ");
            fwrite(buffer, 1, bytesReceived, stdout);  // Safely print raw bytes
            printf("\n");
            
            // Write data to client
            int bytesSent;
            if (clientSocketSSL) {
                bytesSent = SSL_write(clientSocketSSL, buffer, bytesReceived);
                if (bytesSent <= 0) {
                    fprintf(stderr, "SSL_write error to client: %d\n", 
                             SSL_get_error(clientSocketSSL, bytesSent));
                    ERR_print_errors_fp(stderr);
                    break;
                }
            } else {
                bytesSent = send(clientSocket, buffer, bytesReceived, 0);
                if (bytesSent <= 0) {
                    fprintf(stderr, "Send error to client: %s\n", strerror(errno));
                    break;
                }
            }
        }
    }

    // Cleanup resources
    if (clientSocketSSL) {
        SSL_shutdown(clientSocketSSL);
        SSL_free(clientSocketSSL);
    }
    
    if (serverSocketSSL) {
        SSL_shutdown(serverSocketSSL);
        SSL_free(serverSocketSSL);
    }

    close(clientSocket);
    close(serverSocket);
    
    fprintf(stdout, "Tunnel closed\n");
}

void Handler::handleConnectMethod(std::string& request, int clientSocket, IO_FileStream* log_stream, SSL* threadSsl){
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
    SSL* remoteSSL=nullptr;
    int remoteSocket = connectRemoteServer(host.c_str(),port,&remoteSSL);
    if(remoteSocket < 0){
        fprintf(stderr,"error connecting to remote server");
        return;
    }
    std::cout<<"[!] Remote server connected\n";

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
    if(threadSsl) {
        SSL_write(threadSsl, ack.c_str(), ack.length());
    } else {
        send(clientSocket, ack.c_str(), ack.length(), 0);
    }

    // Now let the client and server talk to each other until tunnel is closed
    // Only use SSL tunneling if both connections are secure
    if(threadSsl && remoteSSL) {
        std::cout << "Starting SSL tunnel between client and remote server\n";
        forwardInTunnel(clientSocket, remoteSocket, threadSsl, remoteSSL);
    } else if(threadSsl && !remoteSSL) {
        std::cout << "Client using SSL but remote server not using SSL\n";
        // Handle mixed mode - implement appropriate forwarding
    } else {
        std::cout << "Plain HTTP forwarding\n";
        // Implement plain forwarding
    }
}

SSL_CTX* Handler::serverCtx = nullptr;
void Handler::setServerCTX(SSL_CTX* newServerCTX) {
    serverCtx = newServerCTX;
}
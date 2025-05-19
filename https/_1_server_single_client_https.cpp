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
#include "proxy_parse.h"

#define MAX_BYTES 100    //max allowed size of request/response

int checkHTTPversion(char *msg){
	int version = -1;
	if(strncmp(msg, "HTTP/1.1", 8) == 0){
		version = 1;
	}
	else if(strncmp(msg, "HTTP/1.0", 8) == 0){
		version = 1;										// Handling this similar to version 1.1
	}

	return version;
}

int sendErrorMessage(int socket, int status_code)
{
	char str[1024];
	char currentTime[50];
	time_t now = time(0);

	struct tm data = *gmtime(&now);
	strftime(currentTime,sizeof(currentTime),"%a, %d %b %Y %H:%M:%S %Z", &data);

	switch(status_code)
	{   
        // snprintf writes formatted output into the str buffer, to send buffer to client
		case 400: snprintf(str, sizeof(str), "HTTP/1.1 400 Bad Request\r\nContent-Length: 95\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>400 Bad Request</TITLE></HEAD>\n<BODY><H1>400 Bad Rqeuest</H1>\n</BODY></HTML>", currentTime);
				  printf("400 Bad Request\n");
				  send(socket, str, strlen(str), 0);
				  break;

		case 403: snprintf(str, sizeof(str), "HTTP/1.1 403 Forbidden\r\nContent-Length: 112\r\nContent-Type: text/html\r\nConnection: keep-alive\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>403 Forbidden</TITLE></HEAD>\n<BODY><H1>403 Forbidden</H1><br>Permission Denied\n</BODY></HTML>", currentTime);
				  printf("403 Forbidden\n");
				  send(socket, str, strlen(str), 0);
				  break;

		case 404: snprintf(str, sizeof(str), "HTTP/1.1 404 Not Found\r\nContent-Length: 91\r\nContent-Type: text/html\r\nConnection: keep-alive\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD>\n<BODY><H1>404 Not Found</H1>\n</BODY></HTML>", currentTime);
				  printf("404 Not Found\n");
				  send(socket, str, strlen(str), 0);
				  break;

		case 500: snprintf(str, sizeof(str), "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 115\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>500 Internal Server Error</TITLE></HEAD>\n<BODY><H1>500 Internal Server Error</H1>\n</BODY></HTML>", currentTime);
				  printf("500 Internal Server Error\n");
				  send(socket, str, strlen(str), 0);
				  break;

		case 501: snprintf(str, sizeof(str), "HTTP/1.1 501 Not Implemented\r\nContent-Length: 103\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>404 Not Implemented</TITLE></HEAD>\n<BODY><H1>501 Not Implemented</H1>\n</BODY></HTML>", currentTime);
				  printf("501 Not Implemented\n");
				  send(socket, str, strlen(str), 0);
				  break;

		case 505: snprintf(str, sizeof(str), "HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: 125\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>505 HTTP Version Not Supported</TITLE></HEAD>\n<BODY><H1>505 HTTP Version Not Supported</H1>\n</BODY></HTML>", currentTime);
				  printf("505 HTTP Version Not Supported\n");
				  send(socket, str, strlen(str), 0);
				  break;

		default:  return -1;

	}
	return 1;
}

int connectRemoteServer(char* host_name, int serverPort){
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

void sendFromServerToClientSocket(int serverSocket,int clientSocket){
    int MAX_BUFFER = MAX_BYTES;
    char* buffer = (char*)calloc(MAX_BUFFER,sizeof(char));

    // receive from server and send to client 
    int bytes_received_from_server = recv(serverSocket, buffer, MAX_BUFFER, 0);

    while(bytes_received_from_server > 0){
        // send to client
        sendToSocket(buffer, clientSocket, bytes_received_from_server);

        // empty buffer 
        memset(buffer,0,MAX_BUFFER); 
        bytes_received_from_server = recv(serverSocket, buffer,MAX_BUFFER,0);  
    }

    if(bytes_received_from_server<0){
        fprintf(stderr, "Error while receiving from server");
    }

    free(buffer);
}

int handleRequest(int clientSocket, ParsedRequest* request){
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
    char* header_buffer = (char*)malloc(sizeof(char)*(header_length+1));

    // now convert to a raw http request string from struct into buffer
    if(ParsedRequest_unparse_headers(request,header_buffer,header_length)<0){
        fprintf(stderr,"unparse failed" );
        return -1;
    }

    header_buffer[header_length] = '\0';        // needed to end this header as it is a string for now 

    // allocate a buffer to make a new GET request to the original server 
    // extract the get request to original server by removing details to this proxy server 
    // and making a new get request to original server 
    int requestSize = strlen(request->method) + strlen(request->path) + strlen(request->version) + header_length + 4 ;  // 4 for \r\n\r\n

    // original server request 
    char* serverRequest = (char*)malloc((requestSize+1)*sizeof(char));

    // construct a HTTP request 
    serverRequest[0]='\0';                      // start as an empty string
    strcpy(serverRequest, request->method);              // method
    strcat(serverRequest, " "); 
    strcat(serverRequest, request->path);       // pathname 
    strcat(serverRequest, " ");
    strcat(serverRequest, request->version);    // http version 
    strcat(serverRequest, "\r\n");              // http termination sequence
    strcat(serverRequest, header_buffer);       // headers 

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

    // send data from remote server to cliet 
    sendFromServerToClientSocket(remoteServerSocket, clientSocket);
    
    free(header_buffer);
    free(serverRequest);
    return 0;

    // get the length of buffer i.e number of characters before null character 
    // size_t http_request_buffer_length = strlen(buffer);
}

void* handleClient(void* args)
{
    int socket = *((int*)args);     // create a copy of client socket file descriptor 
    // delete (int*)args;           // double or free corruption error

    int number_of_bytes_send_by_client=0, total_received_bytes_from_client=0;
    std::cout << "Thread started for socket: " << socket << std::endl;

    // create a buffer of max bytes of type char 
    int MAX_BUFFER = MAX_BYTES;
    char* buffer = (char*)calloc(MAX_BUFFER,sizeof(char));
    memset(buffer, 0, MAX_BUFFER);
    number_of_bytes_send_by_client = recv(socket, buffer, MAX_BUFFER,0);       // receive client data 

    // if(strstr(buffer,"CONNECT")){
    //     std::cout<<"CONNECT method is this\n";
    //     std::cout<<buffer<<std::endl;
    // }

    // receive until full request is received 
    while(number_of_bytes_send_by_client > 0){
        total_received_bytes_from_client  += strlen(buffer);

        // if total message received is more than max bytes limit, reallocate double memory size to buffer
        if(total_received_bytes_from_client >= MAX_BUFFER){
            MAX_BUFFER *= 2;    // double the size
            buffer = (char*)realloc(buffer,MAX_BUFFER);
        }

        // check if http termination sequence is found
        if(strstr(buffer,"\r\n\r\n") == NULL){  
            // each time buffer size doubles to receive data
            number_of_bytes_send_by_client = recv(socket, buffer+total_received_bytes_from_client,MAX_BUFFER-total_received_bytes_from_client,0);
        }
        else{
            break;
        }
    }

    // Parse host and port from "CONNECT host:port HTTP/1.1"
    std::cout<<buffer<<std::endl;
    char host[256];
    int port;
    sscanf(buffer, "CONNECT %[^:]:%d", host, &port);

  
    
    // create a copy of buffer 
    int bufferLength = strlen(buffer);
    char* tempRequest = (char*)malloc((sizeof(char)+1)*bufferLength);
    for(int i=0;i<bufferLength;i++){
        tempRequest[i]=buffer[i];
    }

    // check if there is request from client 
    if(number_of_bytes_send_by_client > 0){
        total_received_bytes_from_client = strlen(buffer);
        
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

            // Gracefully exit function instead of abrupt exit(1)
            return NULL;
        }
        else{
            // successfully parsed 
            memset(buffer,0,MAX_BYTES);
            if(!strcmp(request->method,"GET")){
                // if get request 
                if(request->host && request->path && (checkHTTPversion(request->version) == 1)){
                    // handle request
                    // works fine
                    /*
                    std::cout<<request->headers<<"\n"
                            <<request->method<<"\n"
                            <<request->path<<"\n"
                            <<request->version<<"\n"
                            <<request->host<<"\n"
                            <<request->port<<"\n";
                    */ 
                    int res = handleRequest(socket, request);
                    if(res == -1){
                        sendErrorMessage(socket,404);
                    }
                }else{
                    std::cout<<"some error occured"<<std::endl;
                    // close socket 
                    shutdown(socket,SHUT_RDWR);     // No more receptions or transmissions
                    close(socket);

                    // free allocated memory 
                    ParsedRequest_destroy(request);
                    free(buffer);
                    free(tempRequest);

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
                free(buffer);
                free(tempRequest);

                // Gracefully exit function instead of abrupt exit(1)
                return NULL;
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
    // free(tempRequest);

    // Gracefully exit function instead of abrupt exit(1)
    return NULL;
}

int main(int argc, char* argv[])
{
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
            return -1;
    }

    // listening to the assigned socket
    if(listen(serverSocket, 5) < 0){
        fprintf(stderr,"Listen failed\n");
        return 1;
    }
    std::cout<<"Server listening to port"<<PORT<<"\n";

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

        int pid = fork();
        if(pid == 0){
            handleClient((void*)&clientSocket);     // child process running in background
            close(clientSocket);
            _exit(0);
        }else{
            close(clientSocket);                    // parent process
        }
    }
     
    // closing the socket.
    close(serverSocket);

    return 0;
}

// minimal example of forwarding data after CONNECT:
// CONNECT www.google.com:443 HTTP/1.1
// Host: www.google.com:443
// User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
// Proxy-Connection: keep-alive
// Connection: keep-alive


void tunnel(int client_fd, int remote_fd) {
    fd_set fds;
    char buffer[4096];
    while (1) {
        FD_ZERO(&fds);
        FD_SET(client_fd, &fds);
        FD_SET(remote_fd, &fds);
        int max_fd = (client_fd > remote_fd) ? client_fd : remote_fd;

        int activity = select(max_fd + 1, &fds, NULL, NULL, NULL);
        if (activity < 0) break;

        // From client to remote
        if (FD_ISSET(client_fd, &fds)) {
            int n = recv(client_fd, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            send(remote_fd, buffer, n, 0);
        }

        // From remote to client
        if (FD_ISSET(remote_fd, &fds)) {
            int n = recv(remote_fd, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            send(client_fd, buffer, n, 0);
        }
    }

    close(client_fd);
    close(remote_fd);
}

/*
Absolutely! Let's walk through your `tunnel()` function line by line — it is a **TCP tunneling** function used for handling HTTPS (`CONNECT`) requests in a proxy server.

---

### 🔧 Purpose:

Once the client (browser) sends a `CONNECT` request (like `CONNECT www.google.com:443`), your proxy must:

1. Connect to the remote server (e.g., `www.google.com:443`)
2. Let the client and remote server talk **through you** — this is **tunneling**.

The function `tunnel(int client_fd, int remote_fd)` does **bidirectional data forwarding** between:

- `client_fd`: socket to the **browser**
- `remote_fd`: socket to the **remote server (e.g., Google)**

---

### ✅ Step-by-Step Explanation

```c
fd_set fds;
char buffer[4096];
```

- `fds`: A set of file descriptors that `select()` will monitor for readability.
- `buffer`: Temporary storage for received data, 4 KB at a time.

---

### 🔁 Infinite loop

```c
while (1) {
```

- You loop forever until either side closes the connection or there's an error.

---

### 1. **Prepare for `select()`**

```c
FD_ZERO(&fds);
FD_SET(client_fd, &fds);
FD_SET(remote_fd, &fds);
int max_fd = (client_fd > remote_fd) ? client_fd : remote_fd;
```

- `FD_ZERO` clears the set.
- `FD_SET` adds both client and remote sockets to be monitored.
- `max_fd`: Needed for `select()` to know how many file descriptors to scan.

---

### 2. **Wait for activity**

```c
int activity = select(max_fd + 1, &fds, NULL, NULL, NULL);
if (activity < 0) break;
```

- `select()` waits (blocking) until **either** the client or remote server sends data.
- If `select()` returns `< 0`, something went wrong → exit.

---

### 3. **Forward: Client → Remote Server**

```c
if (FD_ISSET(client_fd, &fds)) {
    int n = recv(client_fd, buffer, sizeof(buffer), 0);
    if (n <= 0) break;
    send(remote_fd, buffer, n, 0);
}
```

- `FD_ISSET(client_fd, &fds)` means the **client sent data**.
- Read from client, and forward it to remote server.
- If client disconnected (`n <= 0`), break the loop.

---

### 4. **Forward: Remote Server → Client**

```c
if (FD_ISSET(remote_fd, &fds)) {
    int n = recv(remote_fd, buffer, sizeof(buffer), 0);
    if (n <= 0) break;
    send(client_fd, buffer, n, 0);
}
```

- Same as above, but in the opposite direction: read from remote server and send to client.

---

### 5. **Clean up**

```c
close(client_fd);
close(remote_fd);
```

- When either side disconnects, close both sockets and terminate the tunnel.

---

### 📌 Why is this important?

This enables **secure HTTPS communication** through your proxy, without decrypting it. The proxy acts like a **pipe**, forwarding raw encrypted data in both directions.

---

### 🧪 Tip:

Always return a `200 Connection established` HTTP response to the browser **before** starting this tunnel, or it will not proceed with the TLS handshake.

Example:
```c
char response[] = "HTTP/1.1 200 Connection established\r\n\r\n";
send(client_fd, response, strlen(response), 0);
```

---

Let me know if you want help integrating this into your main request handling code!
*/

/*
Linking c and c++ code 

gcc -c c_code.c -o c_code.o  # Compile C code
g++ -c cpp_code.cpp -o cpp_code.o  # Compile C++ code
g++ cpp_code.o c_code.o -o program  # Link both
./program  # Run the program

*/


// LAXMIBAISHIVHARE P%F-e2Z"P^ScAc^ (Niradhar)
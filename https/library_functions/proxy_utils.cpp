#include<iostream>
#include<cstring>
#include<time.h>
#include<fstream>
#include<cstdio>
#include <mutex>
#include <sys/socket.h>
#include "../headers/proxy_utils.h"

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
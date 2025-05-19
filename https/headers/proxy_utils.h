#ifndef LIBRARY // if not defined
#define LIBRARY

#include<fstream>
#include<ctime>
#include <mutex>
#include<cstring>

int checkHTTPversion(char *msg);
int sendErrorMessage(int socket, int status_code);

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

#endif
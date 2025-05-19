/*
This is a custom function library file

*/

// Required Header files
#include <iostream>
#include <mutex>
#include <condition_variable>

#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <errno.h>

// defining Semaphore
class Semaphore
{
private:
    unsigned long count; // number of process allowed
    std::mutex mtx;      // mutex lock
    std::condition_variable cv;

public:
    // initializing semaphore
    void semaphore_init_(int val=0)
    {
        std::lock_guard<std::mutex> lock(mtx);
        this->count = val;
    }

    // read semaphore value 
    int getValue(int *p){
        std::lock_guard<std::mutex> lock(mtx);
        *p = this->count;
        return *p;
    }

    // wait method
    void acquire()
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [&]()
                {
                    return count > 0; // if true, let process enter cs else suspend
                });
        --count;
    }

    // signal method
    void release()
    {
        std::lock_guard<std::mutex> lock(mtx);
        this->count += 1;
        cv.notify_one(); // bring suspended process from blocked queue to ready queue
    }
};

// Defining Server Sockets connection under each thread
// class ServerSocket
// {
// private:
//     // int reuseOption=1;
// public:
//     // define methods for socket
//     int createSocket()
//     {
//         int serverSocket = socket(
//             AF_INET,     // ipv4 domain family
//             SOCK_STREAM, // tcp type stream
//             0            // protocol type
//         );

//         return serverSocket; // returns socket file descriptor
//     }

//     void setSocketOptions(int serverSocketFD, int reuseOption)
//     {
//         setsockopt(
//             serverSocketFD, // socket file descriptor
//             SOL_SOCKET,     // api level option
//             SO_REUSEADDR,   // reuse address flag
//             (const char *)reuseOption,
//             sizeof(reuseOption));
//     }
// };

// // Defining Client Sockets connection under each thread
// class ClientSocket
// {
// public:
//     // void accept(int serverSocket, )
// };

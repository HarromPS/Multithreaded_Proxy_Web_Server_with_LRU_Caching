/*
This is a custom function library file

*/

#ifndef SEMAPHORE_FILE
#define SEMAPHORE_FILE

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
    void semaphore_init_(int val);

    // read semaphore value 
    int getValue(int *p);

    // wait method
    void acquire();
    
    // signal method
    void release();
};

#endif
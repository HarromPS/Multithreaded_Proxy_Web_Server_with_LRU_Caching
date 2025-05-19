/*
This is a custom function library file

*/

// Required Header files
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <unistd.h>
#include "Semaphore.hpp"

// initializing semaphore
void Semaphore::semaphore_init_(int val)
{
    std::lock_guard<std::mutex> lock(mtx);
    this->count = val;
}

// read semaphore value 
int Semaphore::getValue(int *p){
    std::lock_guard<std::mutex> lock(mtx);
    *p = this->count;
    return *p;
}

// wait method
void Semaphore::acquire()
{
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock, [&]()
            {
                return count > 0; // if true, let process enter cs else suspend
            });
    --count;
}

// signal method
void Semaphore::release()
{
    std::lock_guard<std::mutex> lock(mtx);
    this->count += 1;
    cv.notify_one(); // bring suspended process from blocked queue to ready queue
}

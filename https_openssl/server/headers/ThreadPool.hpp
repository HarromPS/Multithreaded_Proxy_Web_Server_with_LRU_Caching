/*
- for n very large concurrent requests there will be n threds spawned
- consumes very large resources
- overwhelms hardware 
- machine hangs and crashes

- Need to cap the max no of threads getting created 
- e.g web server handling multiple clients simultaneously
- e.g asynchronous processing an messages 

Thread Pool:
- collection of worker threads that are used to execute tasks concurrently
- whenever a thread is needed pick one from the thread pool and perform a task, once task is completed add the thread back to the pool.
- if more requests are there then it is waited.

Components
Task queue (std::queue<std::function<void()>>)
Worker threads (std::vector<std::thread>)
Synchronization (std::mutex, std::condition_variable)
Shutdown logic

So worked threads
- wait for tasks to be submitted
- pick tasks from a queue and execute them.
- reuses threads instead of creating/destroying new ones.
*/

// start 
#ifndef THREAD_POOL
#define THREAD_POOL

// libraries 
#include<thread>    // std::thread
#include<vector>    // storing thread objects
#include<queue>     // storing tasks
#include<mutex>     // thread safe task access
#include<atomic>    // atomic variable 
#include<condition_variable>    // notify worker threads when new task arrives 
#include<functional>    // std::function<void()> generic tasks

class ThreadPool{
private:
    std::vector<std::thread> workers;   // stores all worker threads
    std::queue<std::function<void()>> tasksQueue;   // queue of task(functions) to be picked up by threads and executed
    std::mutex queueMutex;              // protects queue from race condition 
    std::condition_variable cv;         // waits threads until condition is satisfied
    std::atomic<bool> stop;             // atomic flag to safely access from multiple threads 
    std::atomic<int> tasksRemaining;    // remaining tasks to be done
    std::condition_variable allDone;

    // function each thread is executing all the time, when program runs, to get reused and perform tasks
    void workerThread();      

public:
    ThreadPool();
    void startThreads(size_t numberOfThreads);
    ~ThreadPool();
    
    void enqueueTasks(std::function<void()> task);  // function to enqueue tasks
    void waitAll();     // waits for all thread to complete
};

#endif
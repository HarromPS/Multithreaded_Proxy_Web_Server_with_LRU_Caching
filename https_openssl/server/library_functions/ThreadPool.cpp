// implementation of function declared in .hpp file

// libraries 
#include<iostream>   
#include<thread>    // std::thread
#include<vector>    // storing thread objects
#include<queue>     // storing tasks
#include<mutex>     // thread safe task access
#include<atomic>    // atomic variable 
#include<condition_variable>    // notify worker threads when new task arrives 
#include<functional>     // std::function<void()> generic tasks
#include "../headers/ThreadPool.hpp"

// default constructor
ThreadPool::ThreadPool():stop(false){}

// initialize stop variable in initializer list, before entering body
void ThreadPool::startThreads(size_t numberOfThreads){
    for(size_t i=0;i<numberOfThreads;++i){
        // construct a new thread directly inside vector and start each thread 
        // lambda function calls private member function of this object 
        workers.emplace_back([this]() {this->workerThread();});
    }
    std::cout << "Threadpool created\n";
}

// destructor
ThreadPool::~ThreadPool(){
    stop.store(true);       // stop all threads from execution 
    cv.notify_all();        // notify all waiting threads 

    for(std::thread &worker: workers){
        if(worker.joinable()){
            worker.join();          // join thread for safe exit
        }
    }
}

void ThreadPool::enqueueTasks(std::function<void()> task){
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        tasksQueue.push(std::move(task));       // move the ownership to task queue
        ++tasksRemaining;                       // add task
    }
    cv.notify_one();            // wake up one worker to process the task
}

// callable function, which runs a thread and reused after a task is done for other tasks
void ThreadPool::workerThread(){
    // pick up tasks and execute 
    while(!stop.load()) {
        // loop until flag is true
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            cv.wait(lock, [this](){
                return stop.load() || !tasksQueue.empty();      // wait either shutdown or if a task is unavailable
            });

            if(stop.load() || tasksQueue.empty()) return;

            task = std::move(tasksQueue.front());   // pick up task
            tasksQueue.pop();
        }
        // execute task
        task();

        // after task is done
        if(--tasksRemaining == 0){
            std::unique_lock<std::mutex> lock(queueMutex);
            allDone.notify_all();   // notify all threads to wake up when no task is remaining
        }
    }
}

// wait all tasks to complete
void ThreadPool::waitAll(){
    std::unique_lock<std::mutex> lock(queueMutex);
    allDone.wait(lock,[this](){
        return tasksRemaining.load() == 0;  // when all tasks are done then 
    });
}
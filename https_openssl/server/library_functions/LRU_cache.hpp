// implementing LRU cache structure and methods 

#ifndef LRUCACHE_CLASS
#define LRUCACHE_CLASS

#include<iostream>
#include<cstring>
#include<map>
#include<time.h>
#include <mutex>
#include <condition_variable> 

// doubly linked list of Cache element
class cache_element
{
public:
    char* data;         // data response 
    int length;         // size of data 
    char* url;          // requested urls 
    time_t lru_time_track;  // store latest time the element is accessed
    cache_element* next,*prev;
};

class LRUCache
{
private:
    cache_element *head;
    cache_element *tail;
    std::map<std::string, cache_element*> lruMap;
    int maxCacheSize=0;
    int maxCacheElementSize=0;
    int cacheSize=0;
    int capacity=0;
    
    void insertAtHead(cache_element* node);
    void deleteNode(cache_element* node);
    public:
    pthread_mutex_t lock;   // Define mutex

    LRUCache(int MAX_CACHE_SIZE,int MAX_CACHE_ELEMENT_SIZE);    
    LRUCache(int capacity,int MAX_CACHE_SIZE,int MAX_CACHE_ELEMENT_SIZE);
    std::string normalizeUrl(const std::string& url);
    cache_element* find(const char* _url);
    void printList();
    void addElementToCache(char* data_from_server, int data_size,const char* _url);
    ~LRUCache();
};

#endif
/*
int main() {

    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);
    std::cout.tie(NULL);
#ifndef ONLINE_JUDGE
    freopen("./input.txt", "r", stdin);
    freopen("./output.txt", "w", stdout);
#endif

   solve();

    return 0;
}

*/
// implementing LRU cache structure and methods 

#include<iostream>
#include<cstring>
#include<map>
#include<time.h>
#include <mutex>
#include <condition_variable>
#include"LRU_cache.hpp" 

// doubly linked list of Cache element
// class cache_element
// {
// public:
//     char* data;         // data response 
//     int length;         // size of data 
//     char* url;          // requested urls 
//     time_t lru_time_track;  // store latest time the element is accessed
//     cache_element* next,*prev;
// };


void LRUCache::insertAtHead(cache_element* node){
    node->prev = head;
    node->next = head->next;
    head->next = node;
    head->next->prev = node;
}

void LRUCache::deleteNode(cache_element* node){
    node->prev->next = node->next;
    node->next->prev = node->prev;
}


LRUCache::LRUCache(int MAX_CACHE_SIZE,int MAX_CACHE_ELEMENT_SIZE)
{
    this->cacheSize=0;
    this->maxCacheSize=MAX_CACHE_SIZE;
    this->maxCacheElementSize=MAX_CACHE_ELEMENT_SIZE;
    head = (cache_element*)calloc(1,sizeof(cache_element));
    tail = (cache_element*)calloc(1,sizeof(cache_element));

    if (!head || !tail) {
        throw std::runtime_error("Failed to allocate cache nodes");
    }

    head->data = NULL;
    head->length = 0;
    head->url = NULL;
    head->lru_time_track = 0;

    tail->data = NULL;
    tail->length = 0;
    tail->url = NULL;
    tail->lru_time_track = 0;

    head->prev = NULL;
    head->next = tail;
    tail->next = NULL;
    tail->prev = head;
}

LRUCache::LRUCache(int capacity,int MAX_CACHE_SIZE,int MAX_CACHE_ELEMENT_SIZE)
{
    this->cacheSize=0;
    this->capacity=capacity;
    this->maxCacheSize=MAX_CACHE_SIZE;
    this->maxCacheElementSize=MAX_CACHE_ELEMENT_SIZE;
    head = (cache_element*)calloc(1,sizeof(cache_element));
    tail = (cache_element*)calloc(1,sizeof(cache_element));

    if (!head || !tail) {
        throw std::runtime_error("Failed to allocate cache nodes");
    }

    head->data = NULL;
    head->length = 0;
    head->url = NULL;
    head->lru_time_track = 0;

    tail->data = NULL;
    tail->length = 0;
    tail->url = NULL;
    tail->lru_time_track = 0;

    head->prev = NULL;
    head->next = tail;
    tail->next = NULL;
    tail->prev = head;
}

std::string LRUCache::normalizeUrl(const std::string& url) {
    // Strip protocol
    std::string clean_url = url;
    if (clean_url.substr(0, 7) == "http://")
        clean_url = clean_url.substr(7);
    else if (clean_url.substr(0, 8) == "https://")
        clean_url = clean_url.substr(8);

    // Remove trailing slashes
    if (!clean_url.empty() && clean_url.back() == '/')
        clean_url.pop_back();

    return clean_url;
}    

cache_element* LRUCache::find(const char* _url) {
    // acquire mutex lock 
    int mutex_lock_value = pthread_mutex_lock(&lock);
    if (mutex_lock_value != 0) {
        std::cerr << "Failed to acquire lock: " << std::endl;
        return NULL;
    }
    std::cout<<"\nlock acquired to find cache element: "<<std::endl;

    if (!_url || strlen(_url) == 0) return nullptr;
    
    std::string url(_url);
    auto it = lruMap.find(url);
    
    if (it == lruMap.end()) {
        std::cout << "URL not found in cache: " << url << std::endl;
        
        mutex_lock_value = pthread_mutex_unlock(&lock);
        std::cout<<"\nlock released to find cache element: "<<std::endl;
        return nullptr;
    }
    
    // Move to front (LRU logic)
    cache_element* found = it->second;
    deleteNode(found);
    insertAtHead(found);
    found->lru_time_track = time(nullptr);
    
    std::cout << "URL found in cache: " << url << std::endl;

    mutex_lock_value = pthread_mutex_unlock(&lock);
    std::cout<<"\nlock released to find cache element: "<<std::endl;
    return found;
}

void LRUCache::printList(){
    // acquire mutex lock 
    int mutex_lock_value = pthread_mutex_lock(&lock);
    if (mutex_lock_value != 0) {
        std::cerr << "Failed to acquire lock: " << std::endl;
        return;
    }
    std::cout<<"\nlock acquired to print cache element: "<<std::endl;

    for (const auto& pair : lruMap) {
        std::cout << "Stored: " << pair.first << " (len: " << pair.first.length() << ")\n";
    }

    mutex_lock_value = pthread_mutex_unlock(&lock);
    std::cout<<"\nlock released to print cache element: "<<std::endl;
}

void LRUCache::addElementToCache(char* data_from_server, int data_size,const char* _url)
{
    std::cout << "Attempting to cache URL: " << (_url ? _url : "NULL ")<< std::endl;   
    std::string url(_url);

    char* url_copy = strdup(_url);
    if (!url_copy) return;

    int total_element_size = data_size + strlen(_url) + 1;

    // check if element has size more than allowed size
    // auto it = lruMap.find(url); // curr node
    if(total_element_size > this->maxCacheElementSize){
        // do not add element to the cache 
        fprintf(stderr,"Cannot add to cache\n Too much size\n");
    }

    // check if cache is full, make space by removing least used element 
    if(cacheSize + total_element_size > maxCacheSize){
        fprintf(stderr,"cache full\n");
    }

    // acquire mutex lock 
    int mutex_lock_value = pthread_mutex_lock(&lock);
    if (mutex_lock_value != 0) {
        std::cerr << "Failed to acquire lock: " << std::endl;
        return;
    }
    std::cout<<"\nlock acquired to add cache element: "<<std::endl;

    while(cacheSize + total_element_size > maxCacheSize){
        cache_element* temp=tail->prev;
        deleteNode(temp);
        lruMap.erase(temp->url);
        free(temp);
    }

    // create a new node and update 
    cache_element* newNode = (cache_element*)malloc(sizeof(cache_element));
    if (!newNode) {
        fprintf(stderr,"Error adding in cache\n");
        free(url_copy);

        mutex_lock_value = pthread_mutex_unlock(&lock);
        std::cout<<"\nlock released to add cache element: "<<std::endl;
        return;
    }
    newNode->prev=NULL;
    newNode->next=NULL;
    newNode->data=(char*)malloc(data_size+1);
    if (!newNode->data) {
        free(url_copy);
        free(newNode);
        return;
    }
    newNode->url = strdup(url.c_str());

    memcpy(newNode->data, data_from_server, data_size);
    newNode->data[data_size] = '\0';
    newNode->length = total_element_size;

    // update lru time track 
    newNode->lru_time_track = time(NULL);

    lruMap[url]=newNode;
    insertAtHead(newNode);
    fprintf(stdout,"Added to cache\n");
    this->cacheSize += total_element_size; 
    
    mutex_lock_value = pthread_mutex_unlock(&lock);
    std::cout<<"\nlock released to add cache element: "<<std::endl;
}

LRUCache::~LRUCache() {
    // acquire mutex lock 
    int mutex_lock_value = pthread_mutex_lock(&lock);
    if (mutex_lock_value != 0) {
        std::cerr << "Failed to acquire lock: " << std::endl;
        return;
    }
    std::cout<<"\nlock acquired to find cache element: "<<std::endl;

    cache_element* curr = head->next;
    while (curr != tail) {
        cache_element* temp = curr;
        curr = curr->next;
        
        free(temp->data);
        free(temp->url);  // Free the copied URL
        free(temp);
    }
    
    // No need to free head/tail url/data as they're NULL
    free(head);
    free(tail);
    lruMap.clear();

    mutex_lock_value = pthread_mutex_unlock(&lock);
    std::cout<<"\nlock released to remove cache element: "<<std::endl;
}
// implementing LRU cache structure and methods 

#include<iostream>
#include<cstring>
#include<map>
#include<time.h>
#include <mutex>
#include <condition_variable>

pthread_mutex_t lock;   // Define mutex 

/*
// structure of a cached element 
typedef struct cache_element{
    char* data;         // data response 
    int length;         // size of data 
    char* url;          // requested urls 
    time_t lru_time_track;  // store latest time the element is accessed
    cache_element* next;    // pointer to next cached element 
}cache_element;

// implement LRU cache as a linked list 
class LRUCacheElement{
public:
    cache_element *head;
    int maxCacheSize=0;
    int maxCacheElementSize=0;
    int cacheSize=0;

    LRUCacheElement(){}
    LRUCacheElement(int MAX_CACHE_SIZE,int MAX_CACHE_ELEMENT_SIZE){
        this->head=NULL;
        this->cacheSize=0;
        this->maxCacheSize=MAX_CACHE_SIZE;
        this->maxCacheElementSize=MAX_CACHE_ELEMENT_SIZE;

    }

    // cache methods 
    void printCache(){
        cache_element* curr=this->head;
        // for(int i=0;i<3;i++){
        //     std::cout<<curr->url<<"\n";
        //     curr = curr->next;
        //     if(curr == NULL) break;
        // }
        // while(curr!=NULL){
            
        // }
        std::cout<<std::endl;
    }

    // find cached element 
    cache_element* find(char* url){
        // find the url if requested before 

        cache_element* current = this->head;

        // if head is null
        if(this->head == NULL){
            std::cout<<"\nUrl Not Found\n";
            return NULL;
        }

        // find cache element using url 

        cache_element* prev = NULL;
        while(current!=NULL){
            // element found 
            std::cout<<current->url<<" "<<url<<std::endl;
            if(strcmp(current->url,url) == 0){
                std::cout<<"URL found"<<std::endl;
                std::cout<<"Previous LRU time track: "<<current->lru_time_track<<std::endl;
                
                // update lru time track 
                current->lru_time_track = time(NULL);
                std::cout<<"Current LRU time track: "<<current->lru_time_track<<std::endl;

                if (prev != NULL) {
                    prev->next = current->next;
                    current->next = head;
                    head = current;
                }                
                break;
            }
            prev = current;
            current=current->next;
        }
        return current;
    }

    // remove cache element
    void removeElementFromCache(){
        // remove least used element from list 
        // find element with least time track 

        // base case 
        if(head==NULL){
            return;
        }

        if(head->next==NULL){
            cache_element* temp=head;
            head=NULL;

            free(temp->data);
            free(temp->url);
            free(temp);
        }

        cache_element* curr = head;
        cache_element* ans = head;      // lru
        cache_element* temp = NULL;     // prev
        cache_element* prev = NULL;     // lruPrev

        while(curr!=NULL){
            if(ans->lru_time_track > curr->lru_time_track){
                prev=temp;
                ans=curr;
            }
            temp=curr;
            curr=curr->next;
        }

        // check base case 
        if(ans == head){
            cache_element* removeHead = head;
            head = head->next;

            free(removeHead->data);
            free(removeHead->url);
            free(removeHead);
        }else{
            // delete this node 
            prev->next = ans->next;
        }

        // update cache size 
        cacheSize = cacheSize - ((ans->length) + sizeof(cache_element) + strlen(ans->url) + 1);

        // free allocated memory 
        free(ans->data);
        free(ans->url);
        free(ans);
    }

    // add a element in the cache linked list 
    void addElementToCache(char* data_from_server, int data_size, char* url){
        // calculate size of cache element to be stored
        int total_element_size = data_size + strlen(url) +1; // 1 for null terminator 

        // check if element has size more than allowed size
        if(total_element_size > this->maxCacheElementSize){
            // do not add element to the cache 
            fprintf(stderr,"Cannot add to cache\n Too much size\n");
            return;
        }

        // check if cache is full, make space by removing least used element 
        if(cacheSize + total_element_size > maxCacheSize){
            fprintf(stderr,"cache full\n");
        }

        while(cacheSize + total_element_size > maxCacheSize){
            removeElementFromCache();
        }

        // create a copy of element to be added to cache 
        cache_element* tempElement = (cache_element*)malloc(sizeof(cache_element));
        if (!tempElement) return;

        tempElement->data = (char*)malloc(data_size+1);
        tempElement->url = (char*)malloc(strlen(url)+1);
        tempElement->next = NULL;

        // prevent memory leak if malloc failed
        if (!tempElement->data || !tempElement->url){
            fprintf(stderr,"Preventing memory leaks");
            if (tempElement->data) free(tempElement->data);
            if (tempElement->url) free(tempElement->url);
            free(tempElement);
            return;
        }

        // copy data to temp element 
        memcpy(tempElement->data, data_from_server, data_size);  // safer than strcpy
        tempElement->data[data_size] = '\0';  // ensure null termination

        strcpy(tempElement->url, url);
        
        tempElement->length = total_element_size;

        // update lru time track 
        tempElement->lru_time_track = time(NULL);

        // update list 
        tempElement->next = this->head;
        this->head = tempElement;
        fprintf(stdout,"Added to cache\n");

        // update cache size 
        this->cacheSize += total_element_size;

        // for(long unsigned int i=0;i<strlen(url);i++){
        //     std::cout<<url[i];
        // }
        // std::cout<<std::endl;

        // free(tempElement->data);
        // free(tempElement->url);
        // free(tempElement);
    }

    // destructor to free up allocated memory 
    ~LRUCacheElement(){
        cache_element* curr = this->head;
        while(curr != NULL){
            cache_element* temp = curr;
            curr = curr->next;
    
            free(temp->data);
            free(temp->url);
            free(temp);
        }
        this->head = NULL;
    }
      
};

*/

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

    void insertAtHead(cache_element* node){
        node->prev = head;
        node->next = head->next;
        head->next = node;
        head->next->prev = node;
    }

    void deleteNode(cache_element* node){
        node->prev->next = node->next;
        node->next->prev = node->prev;
    }
public:
    // implementing lru cache using doubly linked list and hashmap data structure

    LRUCache(int MAX_CACHE_SIZE,int MAX_CACHE_ELEMENT_SIZE)
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
    
    LRUCache(int capacity,int MAX_CACHE_SIZE,int MAX_CACHE_ELEMENT_SIZE)
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

    std::string normalizeUrl(const std::string& url) {
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

    cache_element* find(const char* _url) {
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

    void printList(){
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

    void addElementToCache(char* data_from_server, int data_size,const char* _url)
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

    ~LRUCache() {
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
};

void solve(){
    // Initialize the cache: capacity = 3, max cache size = 1MB, max element size = 100KB
    LRUCache lruCache(3, 1000000, 100000);

    const char* data1 = "Response from google.com";
    const char* data2 = "Response from yahoo.com";
    const char* data3 = "Response from bing.com";
    const char* data4 = "Response from duckduckgo.com";

    // Add elements
    lruCache.addElementToCache((char*)data1, strlen(data1), "www.google.com/");
    lruCache.addElementToCache((char*)data2, strlen(data2), "www.yahoo.com/");
    lruCache.addElementToCache((char*)data3, strlen(data3), "www.bing.com/");

    std::cout << "\n--- After 3 inserts ---\n";
    lruCache.printList();

    // Access one element to move it to front
    lruCache.find("www.google.com/");

    std::cout << "\n--- After accessing www.google.com/ (should move to front) ---\n";
    lruCache.printList();

    // Insert one more element to trigger LRU removal
    lruCache.addElementToCache((char*)data4, strlen(data4), "www.duckduckgo.com/");

    std::cout << "\n--- After inserting 4th element (capacity is 3, so LRU should be evicted) ---\n";
    lruCache.printList();

    // Try to find an evicted URL (e.g. www.yahoo.com/ if that was the least recently used)
    auto result = lruCache.find("www.yahoo.com/");
    if (result) {
        std::cout << "www.yahoo.com/ found in cache\n";
    } else {
        std::cout << "www.yahoo.com/ NOT found in cache (likely evicted)\n";
    }
}

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
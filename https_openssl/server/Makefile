CC=g++
CCC=gcc
CFLAGS= -g -Wall 
LDFLAGS = -lssl -lcrypto

MAIN_TARGET = server 
MAIN_SRC = server.cpp \
		   library_functions/ssl_library.cpp \
		   library_functions/LRU_cache.cpp \
		   library_functions/proxy_parse.c \
		   library_functions/Semaphore.cpp \
		   library_functions/proxy_utils.cpp \
		   library_functions/ThreadPool.cpp 

MAIN_OBJ_FILES = $(MAIN_SRC:.cpp=.o)

all: $(MAIN_TARGET)

$(MAIN_TARGET): $(MAIN_OBJ_FILES)
	$(CXX) $(CFLAGS) $^ -o $@ $(LDFLAGS) 

# compile different files in a seperate line
# server: server.cpp
# 	$(CC) $(CFLAGS) -o ./library_functions/proxy_parse.o -c ./library_functions/proxy_parse.c 
# 	$(CC) $(CFLAGS) $(LDFLAGS) -o ./library_functions/ssl_library.o -c ./library_functions/ssl_library.cpp 
# 	$(CC) $(CFLAGS) $(LDFLAGS) -o ./library_functions/proxy_utils.o -c ./library_functions/proxy_utils.cpp
# 	$(CC) $(CFLAGS) $(LDFLAGS) -o ./library_functions/LRU_cache.o -c ./library_functions/LRU_cache.cpp
# 	$(CC) $(CFLAGS) $(LDFLAGS) -o ./library_functions/Semaphore.o -c ./library_functions/Semaphore.cpp
# 	$(CC) $(CFLAGS) $(LDFLAGS) -o server.o -c server.cpp -lpthread
# 	$(CC) $(CFLAGS) $(LDFLAGS) -o server server.o ./library_functions/proxy_parse.o ./library_functions/proxy_utils.o -lpthread

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f server library_functions/*.o *.o

tar:
	tar -cvzf ass1.tgz server.c README Makefile ./library_functions/proxy_parse.c ./headers/proxy_parse.h
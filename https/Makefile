CC=g++
CCC=gcc
CFLAGS= -g -Wall 

all: main

# compile c file 
# compile c++ file 
# link both files 
# run the program 

# compile different files in a seperate line
main: _2_server_single_client_http_LRU_Cache.cpp
	$(CC) $(CFLAGS) -o ./library_functions/proxy_parse.o -c ./library_functions/proxy_parse.c 
	$(CC) $(CFLAGS) -o ./library_functions/proxy_utils.o -c ./library_functions/proxy_utils.cpp
	$(CC) $(CFLAGS) -o _2_server_single_client_http_LRU_Cache.o -c _2_server_single_client_http_LRU_Cache.cpp -lpthread
	$(CC) $(CFLAGS) -o main _2_server_single_client_http_LRU_Cache.o ./library_functions/proxy_parse.o ./library_functions/proxy_utils.o -lpthread

clean:
	rm -f main *.o library_functions/*.o

tar:
	tar -cvzf ass1.tgz _2_server_single_client_http_LRU_Cache.c README Makefile ./library_functions/proxy_parse.c ./headers/proxy_parse.h
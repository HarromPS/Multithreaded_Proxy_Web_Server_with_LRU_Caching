CC=g++
CCC=gcc
CFLAGS= -g -Wall 
LDFLAGS = -lssl -lcrypto # to pass extra flags to linked ID like cpp flags

MAIN_TARGET = server 

MAIN_SRC = main.cpp ssl_library.cpp

MAIN_OBJ_FILES = $(MAIN_SRC:.cpp=.o)

# demo:
# 	echo $(MAIN_OBJ_FILES)
# 	echo $(CXX) $(CFLAGS) $^ -o $@ $(LDFLAGS) 

all: $(MAIN_TARGET)

# main: main.o ssl_library.o
#	g++ -g -Wall -lssl -lcrypto main.cpp 
$(MAIN_TARGET): $(MAIN_OBJ_FILES)
	$(CXX) $(CFLAGS) $^ -o $@ $(LDFLAGS) 

%.o: %.cpp	
	$(CXX) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

clean:
	rm -f $(MAIN_OBJ_FILES) $(MAIN_TARGET)

tar:
	tar -cvzf ass1.tgz main.cpp README Makefile ssl_library.c ssl_utils.hpp proxy_utils.cpp


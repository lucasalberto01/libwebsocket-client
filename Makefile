# Compiler  easywsclient.hpp

CC = g++
CFLAGS = -Wall -std=c++11
TARGET = websocket-client.o
SRC = websocket-client.cpp
LIBS = -lboost_system -lboost_thread -lpthread


all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -c $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)


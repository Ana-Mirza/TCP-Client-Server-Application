# Protocoale de comunicatii
# Laborator 7 - TCP
# Echo Server
# Makefile

CFLAGS = -Wall -g -Werror -Wno-error=unused-variable

# Server port
PORT = 8080

# Server IP address
IP_SERVER = 127.0.0.1

# Client ID
ID_CLIENT = C0

all: server subscriber

common.o: common.c

# Compile server.c
server: server.c common.o

# Compile subscriber.c
subscriber: subscriber.c common.o -lm

.PHONY: clean run_server run_subscriber

# Run server
run_server:
	./server ${PORT}

# Run subscriber
run_subscriber:
	./subscriber ${ID_CLIENT} ${IP_SERVER} ${PORT}

clean:
	rm -rf server subscriber *.o *.dSYM

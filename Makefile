# Protocoale de comunicatii
# Laborator 7 - TCP
# Echo Server
# Makefile

CFLAGS = -Wall -g -Werror -Wno-error=unused-variable

# Server port
PORT = 8080

# Server IP addres
IP_SERVER = 127.0.0.1

all: server subscriber

common.o: common.c

# Compile server.c
server: server.c common.o

# Compile subscriber.c
subscriber: subscriber.c common.o

.PHONY: clean run_server run_subscriber

# Ruleaza serverul
run_server:
	./server ${IP_SERVER} ${PORT}

# Ruleaza clientul 	
run_subscriber:
	./subscriber ${IP_SERVER} ${PORT}

clean:
	rm -rf server subscriber *.o *.dSYM

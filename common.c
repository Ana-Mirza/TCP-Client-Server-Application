#include "common.h"

#include <sys/socket.h>
#include <sys/types.h>

/* Receceive exactly len bytes */
int recv_all(int sockfd, void *buffer, size_t len) {

	size_t bytes_received = 0;
	size_t bytes_remaining = len;
	char *buff = buffer;

	while(bytes_remaining) {
		bytes_received += recv(sockfd, buff + bytes_received, bytes_remaining, 0);
		bytes_remaining = len - bytes_received;
	}


	return bytes_received;
}

/* Send exactly len bytes */
int send_all(int sockfd, void *buffer, size_t len) {
	size_t bytes_sent = 0;
	size_t bytes_remaining = len;
	char *buff = buffer;

	while(bytes_remaining) {
		bytes_sent += send(sockfd, buff + bytes_sent, bytes_remaining, 0);
		bytes_remaining = len - bytes_sent;
	}

	return bytes_sent;
}
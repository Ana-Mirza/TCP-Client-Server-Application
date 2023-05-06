#include "common.h"
#include "helpers.h"

#include <sys/socket.h>
#include <sys/types.h>

/* Receceive exactly len bytes */
int recv_all(int sockfd, void *buffer, size_t len) {
	size_t bytes_received = 0;
	size_t bytes_remaining = len;
	char *buff = buffer;

	while(bytes_remaining) {
		int rc = recv(sockfd, buff + bytes_received, bytes_remaining, 0);
		DIE(rc == -1, "recv failed");
		if (rc == 0)
			return rc;

		bytes_received += rc;
		bytes_remaining -= rc;
	}

	return bytes_received;
}

/* Send exactly len bytes */
int send_all(int sockfd, void *buffer, size_t len) {
	size_t bytes_sent = 0;
	size_t bytes_remaining = len;
	char *buff = buffer;

	while(bytes_remaining) {
		int rc = send(sockfd, buff + bytes_sent, bytes_remaining, 0);
		DIE(rc == -1, "send failed");
		if (bytes_sent == 0)
			return bytes_sent;

		bytes_sent += rc;
		bytes_remaining = len - bytes_sent;
	}

	return bytes_sent;
}
/*
 * Protocoale de comunicatii
 * Laborator 7 - TCP si mulplixare
 * client.c
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <poll.h>

#include "common.h"
#include "helpers.h"

void run_client(int sockfd) {
	char buf[MSG_MAXSIZE + 1];
	memset(buf, 0, MSG_MAXSIZE + 1);

	struct chat_packet sent_packet;
	struct chat_packet recv_packet;

	/* Multiplex stdin input and getting a message from server */
	struct pollfd superBET[2];
	superBET[0].fd = STDIN_FILENO;
	superBET[0].events = POLLIN;
	superBET[1].fd = sockfd;
	superBET[1].events = POLLIN;

	while (1) {
		poll(superBET, 2, -1);

		if (superBET[0].revents & POLLIN) {
			fgets(buf, sizeof(buf), stdin);

			sent_packet.len = strlen(buf) + 1;
			strcpy(sent_packet.message, buf);

			/* Use send_all function to send the pachet to the server */
			send_all(sockfd, &sent_packet, sizeof(sent_packet));

		}

		if (superBET[1].revents & POLLIN) {
			/* Receive a message and show it's content */
			int rc = recv_all(sockfd, &recv_packet, sizeof(recv_packet));
			if (rc <= 0) {
			break;
			}

			printf("%s\n", recv_packet.message);
		}
	}
}

int main(int argc, char *argv[]) {
	int sockfd = -1;

	if (argc != 3) {
		printf("\n Usage: %s <ip> <port>\n", argv[0]);
		return 1;
	}

	/* set off buffering */
	setvbuf(stdout, NULL, _IONBF, BUFSIZ);

	/* Parse port as number */
	uint16_t port;
	int rc = sscanf(argv[2], "%hu", &port);
	DIE(rc != 1, "Given port is invalid");

	/* Obtain TCP socket to connect to server */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	DIE(sockfd < 0, "socket");

	/* Complete serv_addr, address family and port for connetction */
	struct sockaddr_in serv_addr;
	socklen_t socket_len = sizeof(struct sockaddr_in);

	memset(&serv_addr, 0, socket_len);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	rc = inet_pton(AF_INET, argv[1], &serv_addr.sin_addr.s_addr);
	DIE(rc <= 0, "inet_pton");

	/* Connect to server */
	rc = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	DIE(rc < 0, "connect");

	run_client(sockfd);

	/* Close connection and socket */
	close(sockfd);

	return 0;
}

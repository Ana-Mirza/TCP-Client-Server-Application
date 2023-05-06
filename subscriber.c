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

char buf[MSG_MAXSIZE + 1];
struct chat_packet sent_packet;
struct chat_packet recv_packet;

void run_client(int sockfd) {
	memset(buf, 0, MSG_MAXSIZE + 1);

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

			/* close client session */
			if (strcmp(buf, "exit\n") == 0) {
				memset(buf, 0, MSG_MAXSIZE + 1);
				sent_packet.len = strlen(buf) + 1;
				strcpy(sent_packet.message, buf);
				send_all(sockfd, &sent_packet, sizeof(sent_packet));
				return;
			}

			/* save input */
			char tmp[strlen(buf) + 1];
			memcpy(tmp, buf, strlen(buf) + 1);

			/* check input */
			int nr = 0;
			int sf = 3, invalid_command = 0;
			char command[20];
			char topic[100];
			char *token = strtok(tmp, " ");
			while (token != NULL) {
				nr++;

				/* save command */
				if (nr == 1) {
					strcpy(command, token);

					/* invalid command */
					if (strcmp(command, "exit") != 0 &&
						strcmp(command, "subscribe") != 0 &&
						strcmp(command, "unsubscribe") != 0) {
						invalid_command = 1;
						break;
					}
				}

				/* save topic */
				if (nr == 2)
					strcpy(topic, token);
				
				/* save sf */
				if (nr == 3)
					sf = atoi(token);
				if (nr > 3)
					break;

				token = strtok(NULL, " ");
			}

			/* invalid command */
			if (nr > 3 || (sf != 0 && sf != 1 && nr != 2) ||
				(strcmp(command, "exit") == 0 && nr > 1) ||
				(strcmp(command, "subscribe") == 0 && nr != 3) ||
				(strcmp(command, "unsubscribe") == 0 && nr != 2) || invalid_command) {
				printf("Commands: exit, subscribe <topic> <sf = 0/1>, unsubscribe <topic>\n");
				continue;
			}

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

			/* close client session */
			if (strcmp(recv_packet.message, "exit") == 0)
				return;
		}
	}
}

int main(int argc, char *argv[]) {
	int sockfd = -1;

	if (argc != 4) {
		printf("\n Usage: %s <id> <ip> <port>\n", argv[0]);
		return 1;
	}

	/* set off buffering */
	setvbuf(stdout, NULL, _IONBF, BUFSIZ);

	/* Parse port as number */
	uint16_t port;
	int rc = sscanf(argv[3], "%hu", &port);
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
	rc = inet_pton(AF_INET, argv[2], &serv_addr.sin_addr.s_addr);
	DIE(rc <= 0, "inet_pton");

	/* Connect to server */
	rc = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	DIE(rc < 0, "connect");

	/* Send client id to server */
	sent_packet.len = strlen(argv[1]) + 1;
	strcpy(sent_packet.message, argv[1]);
	send_all(sockfd, &sent_packet, sizeof(sent_packet));

	/* Run client */
	run_client(sockfd);

	/* Close connection and socket */
	close(sockfd);

	return 0;
}

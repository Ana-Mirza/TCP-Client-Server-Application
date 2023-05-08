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
#include <math.h>
#include <netinet/tcp.h>

#include "common.h"
#include "helpers.h"

char buf[MSG_MAXSIZE + 1];
struct chat_packet sent_packet;
struct chat_packet recv_packet;
struct msg_packet msg;

void print_message() {
	/* parse input */
	char topic[MAX_NAME];
	int data_type = 0;
	char payload[MAX_PAYLOAD];

	memset(&msg, 0, sizeof(struct msg_packet));
	memcpy(&msg.addr, recv_packet.message, sizeof(struct sockaddr_in));
	memcpy(msg.message, recv_packet.message + sizeof(struct sockaddr_in), sizeof(msg.message));

	memcpy(topic, msg.message, 50);
	memcpy(&data_type, msg.message + 50, 1);
	memcpy(payload, msg.message + 51, MAX_PAYLOAD);
	
	/* print message from server */
	char ip[100];
	int port = 0;
	port = ntohs(msg.addr.sin_port);
	strcpy(ip, inet_ntoa(msg.addr.sin_addr));
	printf("%s:%d - %s - ", ip, port, topic);
	fflush(stdout);

	switch (data_type)
	{
		case 0:
		{
			printf("INT - ");
			fflush(stdout);
			uint32_t num;
			uint8_t sign;
			memcpy(&sign, payload, 1);
			memcpy(&num, payload + 1, sizeof(uint32_t));
			num = ntohl(num);
			num = (sign == 1) ? (-num) : num;
			printf("%d\n", num);
			fflush(stdout);
			break;
		}
		case 1:
		{
			printf("SHORT_REAL - ");
			fflush(stdout);
			uint16_t num;
			memcpy(&num, payload, sizeof(uint16_t));
			num = ntohs(num);
			double num_final = (double)(num / (double) 100);
			printf("%.2f\n", num_final);
			fflush(stdout);
			break;
		}
		case 2:
		{
			printf("FLOAT - ");
			fflush(stdout);
			uint8_t sign;
			uint32_t num;
			uint8_t power;
			memcpy(&sign, payload, 1);
			memcpy(&num, payload + 1, sizeof(uint32_t));
			memcpy(&power, payload + 1 + 4, sizeof(uint8_t));
			num = ntohl(num);
			double num_final = num / (double) pow(10, (double)power);
			num_final = (sign == 1) ? (-num_final) : num_final;
			printf("%.*f\n", power, num_final);
			fflush(stdout);
			break;
		}
		case 3:
		{
			printf("STRING - %s\n", payload);
			fflush(stdout);
			break;
		}
		default:
			break;
	}
}

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
				printf("Available commands: exit, subscribe <topic> <sf(0/1)>, unsubscribe <topic>\n");
				continue;
			}

			sent_packet.len = strlen(buf) + 1;
			strcpy(sent_packet.message, buf);

			/* Use send_all function to send the pachet to the server */
			send_all(sockfd, &sent_packet, sizeof(sent_packet));

			/* print status */
			if (strcmp(command, "subscribe") == 0)
				printf("Subscribed to topic.\n");
			else if (strcmp(command, "unsubscribe") == 0)
				printf("Unsubscribed from topic.\n");
			fflush(stdout);
		}

		if (superBET[1].revents & POLLIN) {
			/* Receive a message and show it's content */
			memset(&recv_packet, 0, sizeof(struct chat_packet));
			int rc = recv_all(sockfd, &recv_packet, sizeof(recv_packet));
			if (rc <= 0) {
			break;
			}

			/* close client session */
			if (strcmp(recv_packet.message, "exit") == 0)
				return;

			/* print message received from server */
			print_message();
		}
	}
}

int main(int argc, char *argv[]) {
	int sockfd = -1;

	if (argc != 4) {
		printf("\n Usage: %s <id> <ip> <port>\n", argv[0]);
		fflush(stdout);
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

	/* set off Nagle*/
	int flag = 1;
	rc = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	DIE(rc < 0, "nagle");

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

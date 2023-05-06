/*
 * Protocoale de comunicatii
 * Laborator 7 - TCP
 * Echo Server
 * server.c
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "helpers.h"

#define MAX_CONNECTIONS 32
#define INITIAL_SIZE 5
#define ID_SIZE 20

/* array of clients */
struct client *clients;
int clients_size;
int clients_len;

/* free clients array*/
void free_clients() {
	/* free structures for each client */
	for (int i = 0; i < clients_len; i++) {
		free(clients[i].topics_subscribed);
		free(clients[i].messages_received);
	}
	free(clients);
}

/* return index of client */
int get_client_index(char client_id[ID_SIZE]) {
	for (int i = 0; i < clients_len; i++) {
		if (strcmp(clients[i].id, client_id) == 0)
			return i;
	}

	/* client is new */
	return -1;
}

void update_clients(int clientfd, char client_id[ID_SIZE]) {
	/* get position of client in array */
	int client_index = get_client_index(client_id);

	/* check for new client */
	if (client_index == -1) {
		/* check if clients array is full and resize */
		if (clients_len == clients_size) {
			void *tmp = realloc(clients, clients_size * 2);
			DIE(tmp == NULL, "memory reallocation");
			clients = (struct client*)tmp;
			clients_size *= 2;
		}

		/* add new client in array and initialize structure */
		clients[clients_len].fd = clientfd;
		memcpy(clients[clients_len].id, client_id, ID_SIZE);
		clients[clients_len].is_connected = 1;
		clients[clients_len].topics_subscribed = malloc(INITIAL_SIZE * sizeof(struct topic));
		clients[clients_len].messages_received = malloc(INITIAL_SIZE * sizeof(struct chat_packet));
		clients[clients_len].topics_size = INITIAL_SIZE;
		clients[clients_len].topics_len = 0;
		clients[clients_len].msg_recv_size = INITIAL_SIZE;
		clients[clients_len].msg_recv_len = 0;
		clients_len++;
		return;
	}

	/* update client status */
	clients[client_index].is_connected = 1;
}

void run_chat_multi_server(int listenfd) {

	struct pollfd poll_fds[MAX_CONNECTIONS];
	int num_clients = 2;
	int rc;

	struct chat_packet received_packet;

	/* Set socket listefd for listening */
	rc = listen(listenfd, MAX_CONNECTIONS);
	DIE(rc < 0, "listen");

	/* Add listenfd and stdin in read_fds */
	poll_fds[0].fd = listenfd;
	poll_fds[0].events = POLLIN;
	poll_fds[1].fd = STDIN_FILENO;
	poll_fds[1].events = POLLIN;

	/* wait for messages from clients or stdin */
	while (1) {

	rc = poll(poll_fds, num_clients, -1);
	DIE(rc < 0, "poll");

		for (int i = 0; i < num_clients; i++) {
			if (poll_fds[i].revents & POLLIN) {
				if (poll_fds[i].fd == listenfd) {
					/* -------------------- new conection request -------------------- */
					struct sockaddr_in cli_addr;
					socklen_t cli_len = sizeof(cli_addr);
					int newsockfd =
						accept(listenfd, (struct sockaddr *)&cli_addr, &cli_len);
					DIE(newsockfd < 0, "accept");

					/* server is already full, close conection */
					if (num_clients == MAX_CONNECTIONS) {
						printf("Server is full, try again later.\n");
						close(newsockfd);
						continue;
					}

					/* add new socket to file descriptors */
					poll_fds[num_clients].fd = newsockfd;
					poll_fds[num_clients].events = POLLIN;
					num_clients++;

					printf("New client <ID_CLIENT> connected from %d:%d.\n", 
					inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
					/* TEMPORARY */
					printf("Socket fd client %d\n", newsockfd);

					/* get client id */
					char client_id[ID_SIZE];
					recv(newsockfd, client_id, sizeof(client_id), 0);

					/* update client status */
					update_clients(newsockfd, client_id);
					continue;
				} else if (poll_fds[i].fd == STDIN_FILENO) {
					/* -------------------- received input from stdin -------------------- */
					int rc = recv_all(poll_fds[i].fd, &received_packet,
									sizeof(received_packet));
					DIE(rc < 0, "recv");

					/* check input message */
					if (strcmp(received_packet.message, "exit") == 0) {
						/* close all conections and exit */
						for (int j = 0; j < num_clients; j++) {
							if (poll_fds[j].fd != listenfd || poll_fds[j].fd != STDIN_FILENO)
								close(poll_fds[j].fd);
						}

						return;
					} else {
						printf("Commands available: exit\n");
					}
					continue;

				} else {
					/* -------------------- received data from tcp client -------------------- */
					int rc = recv_all(poll_fds[i].fd, &received_packet,
									sizeof(received_packet));
					DIE(rc < 0, "recv");

					if (rc == 0) {
						/* ----------- tcp conection closed ----------- */
						printf("Socket-ul client %d a inchis conexiunea\n", i);
						close(poll_fds[i].fd);

						/* remove client fd from poll */
						for (int j = i; j < num_clients - 1; j++) {
							poll_fds[j] = poll_fds[j + 1];
						}

						num_clients--;

					} else {
						/* ----------- received tcp message ----------- */
						printf("S-a primit de la clientul de pe socketul %d mesajul: %s\n",
								poll_fds[i].fd, received_packet.message);
						/* send message to all other clients */
						for (int j = 0; j < num_clients; j++) {
							if (poll_fds[j].fd == listenfd || poll_fds[i].fd == poll_fds[j].fd
								|| poll_fds[j].fd == STDIN_FILENO)
								continue;

							int rc = send_all(poll_fds[j].fd, &received_packet, sizeof(received_packet));
							DIE(rc < 0, "recv");
						}
					}
				}
			}
		}
	}
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("\n Usage: %s <port>\n", argv[0]);
		return 1;
	}

	/* set off buffering */
	setvbuf(stdout, NULL, _IONBF, BUFSIZ);

	/* parse input port as number */
	uint16_t port;
	int rc = sscanf(argv[1], "%hu", &port);
	DIE(rc != 1, "Given port is invalid");

	/* create TCP socket for conections */
	int listenfd = socket(AF_INET, SOCK_STREAM, 0);
	DIE(listenfd < 0, "socket");

	/* Coplete serv_addr, address family and port for server connection */
	struct sockaddr_in serv_addr;
	socklen_t socket_len = sizeof(struct sockaddr_in);

	/* make socket address reusable */
	int enable = 1;
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
		perror("setsockopt(SO_REUSEADDR) failed");

	memset(&serv_addr, 0, socket_len);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	char addr[20] = "127.0.0.1";
	rc = inet_pton(AF_INET, addr, &serv_addr.sin_addr.s_addr);
	DIE(rc <= 0, "inet_pton");

	/* Associate server address with creted socket using bind */
	rc = bind(listenfd, (const struct sockaddr *)&serv_addr, sizeof(serv_addr));
	DIE(rc < 0, "bind");

	run_chat_multi_server(listenfd);

	/* free array of clients */
	if (clients)
		free_clients();

	/* close listen socket */
	close(listenfd);

	return 0;
}

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

/* send and receive buffers */
char buf[MSG_MAXSIZE + 1];
struct chat_packet received_packet;
struct chat_packet sent_packet;

/* free clients array*/
void free_clients() {
	/* free structures for each client */
	for (int i = 0; i < clients_len; i++) {
		free(clients[i].topics_subscribed);
		free(clients[i].messages_received);
	}
	free(clients);
}

int get_clientfd_index(int fd) {
	for (int i = 0; i < clients_len; i++) {
		if (clients[i].fd == fd)
			return i;
	}
	return -1;
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

int update_clients(int clientfd, char client_id[ID_SIZE]) {
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
		clients[clients_len].messages_received = malloc(INITIAL_SIZE * sizeof(struct msg_packet));
		clients[clients_len].topics_size = INITIAL_SIZE;
		clients[clients_len].topics_len = 0;
		clients[clients_len].msg_recv_size = INITIAL_SIZE;
		clients[clients_len].msg_recv_len = 0;
		clients_len++;
		return 0;
	}

	/* check if client is already in use */
	if (clients[client_index].is_connected) {
		/* send exit message to client */
		sent_packet.len = strlen("exit") + 1;
		strcpy(sent_packet.message, "exit");
		send_all(clientfd, &sent_packet, sizeof(sent_packet));

		/* close connection */
		close(clientfd);
		printf("Client %s already connected.\n", client_id);
		return -1;
	}

	/* update client status */
	clients[client_index].is_connected = 1;
	return 0;
}

/* return index of topic in list of topics */
int get_topic_index(char topic[MAX_NAME], int index) {
	for (int i = 0; i < clients[index].topics_len; i++) {
		if (strcmp((clients[index].topics_subscribed)[i].name, topic) == 0) {
			return i;
		}
	}

	return -1;
}

void print_topics(int index) {
	printf("topics for client %s\n", clients[index].id);
	for (int i = 0; i < clients[index].topics_len; i++) {
		printf("%d. topic name: %s sf: %d\n", i,
				clients[index].topics_subscribed[i].name, clients[index].topics_subscribed[i].sf);
	}
	printf("\n");
}

void run_chat_multi_server(int listenfd, int udpfd) {

	struct pollfd poll_fds[MAX_CONNECTIONS];
	int num_clients = 3;
	int rc;

	/* Set socket listefd for listening */
	rc = listen(listenfd, MAX_CONNECTIONS);
	DIE(rc < 0, "listen");

	/* Add listenfd and stdin in read_fds */
	poll_fds[0].fd = listenfd;
	poll_fds[0].events = POLLIN;
	poll_fds[1].fd = STDIN_FILENO;
	poll_fds[1].events = POLLIN;
	poll_fds[2].fd = udpfd;
	poll_fds[2].events = POLLIN;

	/* wait for messages from clients or stdin */
	while (1) {
		printf("NEW ROUND OF WHILE\n");

		rc = poll(poll_fds, num_clients, -1);
		DIE(rc < 0, "poll");

		for (int i = 0; i < num_clients; i++) {
			if (poll_fds[i].revents & POLLIN) {
				if (poll_fds[i].fd == listenfd) {
					// printf("NEW CONNECTION\n");
					/* -------------------- new conection request -------------------- */
					struct sockaddr_in cli_addr;
					socklen_t cli_len = sizeof(cli_addr);
					int newsockfd =
						accept(listenfd, (struct sockaddr *)&cli_addr, &cli_len);
					DIE(newsockfd < 0, "accept");

					/* get client id */
					int rc = recv_all(newsockfd, &received_packet,
									sizeof(received_packet));
					DIE(rc < 0, "recv");

					/* server is already full, close conection */
					if (num_clients == MAX_CONNECTIONS) {
						printf("Server is full, try again later.\n");
						close(newsockfd);
						continue;
					}

					printf("New client %s connected from %s:%d.\n", received_packet.message,
					inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
					/* TEMPORARY */
					// printf("Socket fd client %d: %d\n", num_clients, newsockfd);

					/* update client status */
					rc = update_clients(newsockfd, received_packet.message);

					/* add new socket to file descriptors if client is valid */
					if (rc != -1) {
						poll_fds[num_clients].fd = newsockfd;
						poll_fds[num_clients].events = POLLIN;
						poll_fds[num_clients].revents = 0;
						num_clients++;
					}
					continue;
				} else if (poll_fds[i].fd == STDIN_FILENO) {
					/* -------------------- received input from stdin -------------------- */
					memset(buf, 0, MSG_MAXSIZE + 1);
					fgets(buf, sizeof(buf), stdin);
					printf("RECEIVED INPUT DATA: %s\n", buf);

					/* check input message */
					if (strncmp(buf, "exit\n", strlen(buf)) == 0) {
						printf("received EXIT command\n");
						/* close all conections and exit */
						for (int j = 0; j < num_clients; j++) {
							if (poll_fds[j].fd != listenfd && poll_fds[j].fd != STDIN_FILENO
								&& poll_fds[j].fd != udpfd) {
								/* send exit message to client */
								sent_packet.len = strlen("exit") + 1;
								strcpy(sent_packet.message, "exit");
								send_all(poll_fds[j].fd, &sent_packet, sizeof(sent_packet));

								/* close connection with client */
								close(poll_fds[j].fd);
							}
						}

						printf("ended\n");
						return;
					} else {
						/* invalid command */
						printf("Commands available: exit\n");
					}
					continue;

				} else if (poll_fds[i].fd == udpfd) {
					/* -------------------- received data from udp client -------------------- */
					int rc = recv_all(poll_fds[i].fd, &received_packet,
									sizeof(received_packet));
					DIE(rc < 0, "recv");

					/* send message to all clients that are subscribed to topic */
				} else {
					/* -------------------- received data from tcp client -------------------- */
					int rc = recv_all(poll_fds[i].fd, &received_packet,
									sizeof(received_packet));
					DIE(rc < 0, "recv");

					if (rc == 0) {
						/* ----------- tcp conection closed ----------- */

						/* update client status */
						int index = get_clientfd_index(poll_fds[i].fd);
						DIE(index < 0, "wrong index");

						clients[index].is_connected = 0;
						close(poll_fds[i].fd);

						/* remove client fd from poll */
						for (int j = i; j < num_clients - 1; j++) {
							poll_fds[j] = poll_fds[j + 1];
						}

						num_clients--;
						printf("Client %s disconnected.\n", clients[index].id);
						continue;
					} else {
						/* ----------- received tcp message ----------- */
						printf("S-a primit de la clientul de pe socketul %d mesajul: %s\n",
								poll_fds[i].fd, received_packet.message);

						/* parse message */
						int nr = 0, sf = 3;
						char command[20];
						char topic[100];
						char *token = strtok(received_packet.message, " ");
						while (token != NULL) {
							nr++;

							/* save command */
							if (nr == 1)
								strcpy(command, token);

							/* save topic */
							if (nr == 2)
								strcpy(topic, token);
							
							/* save sf */
							if (nr == 3)
								sf = atoi(token);

							token = strtok(NULL, " \n");
						}

						/* get client index */
						int index = get_clientfd_index(poll_fds[i].fd);
						DIE(index < 0, "wrong index");

						/* subscribe command received */
						if (strcmp(command, "subscribe") == 0) {
							/* check if topic is already subscribed to */
							int topic_index = get_topic_index(topic, index);
							
							/* subscribe user to new topic */
							if (topic_index == -1) {
								/* check if list of topics needs resize */
								if (clients[index].topics_len == clients[index].topics_size) {
									void *tmp = realloc(clients[index].topics_subscribed,
														clients[index].topics_size * 2);
									DIE(tmp == NULL, "realloc failed");
									clients[index].topics_subscribed = (struct topic*)tmp;
									clients[index].topics_size *= 2;
								}

								/* add topic in list of topics */
								int idx = clients[index].topics_len++;
								memcpy(clients[index].topics_subscribed[idx].name, topic, MAX_NAME);
								clients[index].topics_subscribed[idx].sf = sf;
							} else {
								/* udpate sf with latest choice */
								(clients[index].topics_subscribed)[topic_index].sf = sf;
							}
							print_topics(index);
							continue;
						}

						/* unsubscribe command received */
						if (strcmp(command, "unsubscribe") == 0) {
							int topic_index = get_topic_index(topic, index);
							
							/* remove topic from list of topics */
							if (topic_index != -1) {
								for (int j = topic_index; j < clients[index].topics_len - 1; j++) {
									memcpy(clients[index].topics_subscribed[j].name,
										   clients[index].topics_subscribed[j + 1].name,
										   MAX_NAME);
									clients[index].topics_subscribed[j].sf = clients[index].topics_subscribed[j + 1].sf;
								}

								clients[index].topics_len--;
							}
						}
						
						print_topics(index);
						continue;
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

	/* Complete serv_addr, address family and port for server connection */
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
	DIE(rc < 0, "bind listenfd");

	/* create udp socket */
	int udpfd = socket(AF_INET, SOCK_DGRAM, 0);
	rc = bind(udpfd, (const struct sockaddr *)&serv_addr, sizeof(serv_addr));
	DIE(rc < 0, "bind udpfd");

	/* initialize clients array */
	clients = malloc(INITIAL_SIZE * sizeof(struct client));
	clients_size = INITIAL_SIZE;
	clients_len = 0;

	/* run server */
	run_chat_multi_server(listenfd, udpfd);

	/* free array of clients */
	if (clients)
		free_clients();

	/* close listen and udp sockets */
	close(listenfd);
	close(udpfd);

	return 0;
}

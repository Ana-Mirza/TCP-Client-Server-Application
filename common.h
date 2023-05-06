#ifndef __COMMON_H__
#define __COMMON_H__

#include <stddef.h>
#include <stdint.h>

int send_all(int sockfd, void *buff, size_t len);
int recv_all(int sockfd, void *buff, size_t len);

/* MAximum length of message */
#define MSG_MAXSIZE 1024
#define MAX_NAME 100

/* strcture for a message received/sent */
struct chat_packet {
  uint16_t len;
  char message[MSG_MAXSIZE + 1];
};

/* structure of a topic */
struct topic {
  char name[MAX_NAME];
  int sf;
};

/* structure for a client */
struct client {
  int fd;
  char id[MAX_NAME];
  int is_connected;
  struct topic *topics_subscribed;
  struct chat_packet *messages_received;
  int topics_size;
  int topics_len;
  int msg_recv_size;
  int msg_recv_len;
};

#endif

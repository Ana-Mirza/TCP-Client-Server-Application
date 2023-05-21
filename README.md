#### Name: Ana-Maria Mirza
#### Group: 321CA

#
# Pcom Homework 2

## Overview
This homework implicated creating a client-server application in which the
server acts as a 'broker', delivering messages on some topic received from udp 
clients to tcp clients subscribed to that specific topic. Since clients are 
not always connected to the server, the server uses a mechanism called 
store-and-forward (sf) to store messages received and deliver them to 
subcribed clients when they connect back.


## Data Structures
* struct client - structure used to save status of a client

    - int fd - stores client fd
    - char id[] = stores client id
    - int is_connected - stores whether the client is connected or not
    - struct topic *topics_subscribed - list of topics subscribed to
    - struct msg_packet **messages_received - list of messages received when 
                                              client was not online, 
    - size and length of topic and messages lists for resize purposes

* struct topic - used to describe a topic subscribed by a client

    - char name[] - stores name of the topic
    - int sf - flag for sf; if 0, the client loses all messages sent on that 
                topic if he is not connected to server, else if 1, the client 
                receiceives all messages sent when he connectes back

* struct msg_packet - used to store messages that are stored for when the 
                      client connects back

    - uint_16 duplicates - keeps the number of duplicate messages (number of 
                           clients that need to receive this message and are 
                           not connected)
    - struct sockaddr_in addr - stores address of udp client that send the 
                                message
    - char message[] - stores message to be sent

* struct chat_packet - used to store messages sent and received over sockets

    - uint16_t len - stores number of bytes to be sent/received
    - char message[] - stores message to be sent/received

## Flow of the Application
### 1. Server
Whenever the server receives a new connection from a client, the internal 
array of clients is checked. In this manner, the server checks whether the 
client is new, already known, or already connected. If the client is new, the 
array of clients is updated with a new structure for the new client. If the 
client is known, meaning that the client has connected previously, the server 
only updates his status and sends any waiting messages in his list. Otherwise, 
if the client is already connected, the server send an exit message to the 
client, and closes the connection.

Message are printed to stdout by the server only when a client connects, 
disconnects, or tries to connect with an id already connected.

The server can receives messages to be transmitted from udp clients. When the 
server receives such a packet, the array of clients is checked and all clients 
that are online and subscribed to the topic of the message, are sent the 
message. Then, clients that are not online but subscribed with a sf = 1, have 
the package placed in their list of awayting messages.

The server can also receive messages from its tcp clients. The messages are 
either a subscribe, unsubscribe, or exit. For a subscribe command, the server 
stores internally for the specific client the topic subscribed and the sf 
chosen for that topic. If the topic was already subscribed to, the server 
updates the sf choice of the topic. If the message received is an unsubscribe 
command, the server deletes from the list of subscribed topics that topic. 
Otherwise, it the command is exit, the server saves internally that the client 
is offline.

Lastly, the server can receive messages from standard input. Only the 'exit' 
command is permitted, making the server close all of its connections and exit. 
The server also send all of its connection the exit command so that they also 
exit successfully, clearing all their memory.

### 2. Subscribers/TCP Clients
Tcp clients can receive messages from standard input and from the server. They 
subscribe to certain topics and receive from the server messages placed on 
that topic by the udp clients.

From stdin, the clients can take a subscribe, unsubscribe, or exit command.
The format permitted is the following:

    subscribe <topic> <sf> 
    unsubscribe <topic>
    exit

If the input does not match any of those commands with permitted parameters,
a specific error message will appear, allowing for another command to be
introduced. Also, the values accepted for the sf are only 1 and 0. 

The client prints messages received from the server in the following format:

    <IP_CLIENT_UDP>:<PORT_CLIENT_UDP> - <TOPIC> - <DATA_TYPE> - <MESSAGE>

## Scalability
* Multiplexing - both the server and the tcp clients use poll for multiplexing
                 messages received from stdin/server/client
* Number of clients/messages permitted - the number of clients and messages is 
                                         limited only by the memory available 
                                         for the program; the server uses 
                                         resizeable arrays to store them so
                                         that they are not limited internally
* Memory - the application is memory friendly since all messages stored by the 
           server for clients that are not online are stored as a single
           structure allocated dynamically; since the structure keeps track
           of the number of "duplicates", it ensures that only one packet is
           stored in memory at a time and when the last client received the
           message, the memory for the structure is freed

For subscribe and unsubscribed commands, the client sends the message to the 
server to save it internally, then prints a message. For the exit command, the 
client simply exits.


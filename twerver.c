#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include "socket.h"

#ifndef PORT
    #define PORT 57170
#endif

#define LISTEN_SIZE 5
#define WELCOME_MSG "Welcome to CSC209 Twitter! Enter your username: \r\n"
#define SEND_MSG "send"
#define SHOW_MSG "show"
#define FOLLOW_MSG "follow"
#define UNFOLLOW_MSG "unfollow"
#define BUF_SIZE 256
#define MSG_LIMIT 8
#define FOLLOW_LIMIT 5

struct client {
    int fd;
    struct in_addr ipaddr;
    char username[BUF_SIZE];
    char message[MSG_LIMIT][BUF_SIZE]; 
    struct client *following[FOLLOW_LIMIT]; // Clients this user is following
    struct client *followers[FOLLOW_LIMIT]; // Clients who follow this user
    char inbuf[BUF_SIZE]; // Used to hold input from the client
    char *in_ptr; // A pointer into inbuf to help with partial reads
    struct client *next;
    int num_following; // Number of users this user is currently following
    int num_followers; // Number of users who are following this user
    int num_messages; // Number of messages that this user has sent to its followers
};


// Provided functions. 
void add_client(struct client **clients, int fd, struct in_addr addr);
void remove_client(struct client **clients, int fd);

// These are some of the function prototypes that we used in our solution 
// You are not required to write functions that match these prototypes, but
// you may find them helpful when thinking about operations in your program.

// Send the message in s to all clients in active_clients. 
void announce(struct client *active_clients, char *s);

// Move client c from new_clients list to active_clients list. 
void activate_client(struct client *c, 
    struct client **active_clients_ptr, struct client **new_clients_ptr);


// The set of socket descriptors for select to monitor.
// This is a global variable because we need to remove socket descriptors
// from allset when a write to a socket fails. 
fd_set allset;

/* 
 * Create a new client, initialize it, and add it to the head of the linked
 * list.
 */
void add_client(struct client **clients, int fd, struct in_addr addr) {
    struct client *p = malloc(sizeof(struct client));
    if (!p) {
        perror("malloc");
        exit(1);
    }

    printf("Adding client %s\n", inet_ntoa(addr));
    p->fd = fd;
    p->ipaddr = addr;
    p->username[0] = '\0';
    p->in_ptr = p->inbuf;
    p->inbuf[0] = '\0';
    p->next = *clients;
    p->num_followers = 0;
    p->num_following = 0;
    p->num_messages = 0;

    // initialize messages to empty strings
    for (int i = 0; i < MSG_LIMIT; i++) {
        p->message[i][0] = '\0';
    }

    *clients = p;

}

void add_client_to_list(struct client **clients, struct client *p) {
    p->next = *clients;
    *clients = p;
}

void remove_following(struct client *host, struct client *target_user) {
    // Remove target_user from the host's following list. 
    // After this operation, the host no longer follows target_user.

    int i, j;                         
    for (i = 0; i < host->num_following; i++) {
        if (host->following[i] == target_user) {
            host->following[i] = NULL;
            break;
        }
    }

    if (i < host->num_following - 1) {
        struct client *tmp;
        for (j = i; j < host->num_following - 1; j++) {
            tmp = host->following[j + 1];
            host->following[j] = tmp;
        }
        host->following[j + 1] = NULL;
    }

    host->num_following -= 1;

}

void remove_follower(struct client *host, struct client *target_user) {
    // Remove target user from the host's follower list
    // After this operation, the target_user does not follow host

    int i, j;
    for (i = 0; i < host->num_followers; i++) {
        if (host->followers[i] == target_user) {
            host->followers[i] = NULL;
            break;
        }
    }

    if (i < host->num_followers - 1) {
        struct client *tmp;
        for (j = i; j < host->num_followers - 1; j++) {
            tmp = host->followers[j + 1];
            host->followers[j] = tmp;
        }
        host->followers[j + 1] = NULL;
    }

    host->num_followers -= 1;
}

/* 
 * Remove client from the linked list and close its socket.
 * Also, remove socket descriptor from allset.
 */
void remove_client(struct client **clients, int fd) {
    struct client **p;

    for (p = clients; *p && (*p)->fd != fd; p = &(*p)->next)
        ;

    // Now, p points to (1) top, or (2) a pointer to another client
    // This avoids a special case for removing the head of the list
    if (*p) {

        int n_follow = (*p)->num_following;
        for (int i = 0; i < n_follow; i++) {
            remove_follower(((*p)->following)[i], *p);
        }

        int n_follower = (*p)->num_followers;
        for (int i = 0; i < n_follower; i++) {
            remove_following(((*p)->followers)[i], *p);
        }

        // Remove the client
        struct client *t = (*p)->next;
        printf("Removing client %d %s\n", fd, inet_ntoa((*p)->ipaddr));
        FD_CLR((*p)->fd, &allset);
        close((*p)->fd);
        free(*p);
        *p = t;
    } else {
        fprintf(stderr, 
            "Trying to remove fd %d, but I don't know about it\n", fd);
    }
}

void remove_client_from_new_list(struct client **clients, int fd) {
    // Simply remove a client from the list, not removing any information about the client
    struct client **p;

    for (p = clients; *p && (*p)->fd != fd; p = &(*p)->next)
        ;

    if (*p) {
        struct client *t = (*p)->next;
        *p = t;

    } else {
        fprintf(stderr, 
            "Trying to remove fd %d, but I don't know about it\n", fd);
    }


}

int find_network_newline(struct client *p, int is_command) {
    // Check if the buffer contains a network newline. 
    // If a network newline exists, notify it and replace it with a null terminator.

    int i = 0;
    for (i = 0; &(p->inbuf[i]) != p->in_ptr; i++) {
        if (p->inbuf[i] == '\n') {
            if (i != 0 && p->inbuf[i - 1] == '\r') {
                p->inbuf[i - 1] = '\0';

                if (is_command == 1) {
                    printf("[%d] Found newline: %s\n", p->fd, p->inbuf);                    
                } else {
                    printf("[%d] Found newline %s\n", p->fd, p->inbuf);
                }

                return i + 1;
            }
        }
    }
    return -1;
}


char* extract_username_from_follow(char *cmd) {
    // Extract the username from the "follow command"
    int length = strlen(cmd) - 7;
    char *name = malloc(sizeof(length + 1));
    if (!name) {
        perror("malloc");
        exit(1);
    }
    strncpy(name, &cmd[7], length);
    name[length] = '\0';
    return name;
}

char* extract_username_from_unfollow(char *cmd) {
    // Extract the username from the "unfollow" command
    int length = strlen(cmd) - 9;
    char *name = malloc(sizeof(length + 1));
    if (!name) {
        perror("malloc");
        exit(1);
    }
    strncpy(name, &cmd[9], length);
    name[length] = '\0';
    return name;
}


char* extract_message(char *cmd) {
    // Extract the message from the "send" command
    int length = strlen(cmd) - 5;
    char *message = malloc(sizeof(length + 1));
    if (!message) {
        perror("malloc");
        exit(1);
    }
    strncpy(message, &cmd[5], length);
    message[length] = '\0';
    return message;
}


struct client* username_exists(char *name, struct client **active_clients) {
    // Check if a username <name> exists in the current active_clients list
    struct client *p;
    for (p = *active_clients; p != NULL; p = p->next) {
        if (strcmp(name, p->username) == 0) {
            return p;
        }
    }
    return NULL;
}


int check_command(char *target) {
    // Check the validity of the command and figure out which kind of command it is
    if (strlen(target) == 0) {
        return -1;
    } else {

        if (strlen(target) > 6 && strncmp(target, FOLLOW_MSG, 6) == 0) {
            return 1;
        } else if(strlen(target) > 8 && strncmp(target, UNFOLLOW_MSG, 8) == 0) {
            return 2;
        } else if (strcmp(target, SHOW_MSG) == 0) {
            return 3;
        } else if (strlen(target) > 4 && strncmp(target, SEND_MSG, 4) == 0) {
            return 4;
        } else if (strcmp(target, "quit") == 0) {
            return 5;
        } else {
            return -1;
        }

    }
}

void notify_client(struct client *whom, char* message) {
    // Notify the client with appropriate message
    if (write(whom->fd, message, strlen(message)) == -1) {
        fprintf(stderr, "Write to client %s failed\n", inet_ntoa(whom->ipaddr));
    }
}


void process_follow(struct client *caller, struct client **active_clients) {
    char *name = extract_username_from_follow(caller->inbuf);
    int can_follow;
    struct client *to_follow;

    // Check if follow operation can be performed
    if (username_exists(name, active_clients) != NULL) {
        to_follow = username_exists(name, active_clients);
        if (caller->num_following == FOLLOW_LIMIT) {
            can_follow = -1;
        } else if (to_follow->num_followers == FOLLOW_LIMIT) {
            can_follow = -2;
        } else {
            can_follow = 1;
        }

    } else {
        can_follow = 0;
    }

    if (can_follow > 0) {
        // If follow operation can be performed, execute the operation
        caller->following[caller->num_following] = to_follow;
        caller->num_following += 1;

        to_follow->followers[to_follow->num_followers] = caller;
        to_follow->num_followers += 1;
        printf("%s is following %s\n", caller->username, to_follow->username);
        printf("%s has %s as a follower\n", to_follow->username, caller->username);

    } else if (can_follow == 0) {
        // If not active user
        notify_client(caller, "The username you typed is not an active user\r\n");

    } else if (can_follow == -1) {
        // If the user already has FOLLOW_LIMIT followings
        notify_client(caller, "Number of maximum following exceeded\r\n");

    } else if (can_follow == -2) {
        // If the user to follow already has FOLLOW_LIMIT followers
        notify_client(caller, "Number of maximum followers of username exceeded\r\n");
    }

    free(name);
}



void process_unfollow(struct client *caller, struct client **active_clients) {
    char *name = extract_username_from_unfollow(caller->inbuf);
    int can_unfollow;
    struct client *followed_user;

    // Check if unfollow operation can be performed
    if (username_exists(name, active_clients) != NULL) {
        followed_user = username_exists(name, active_clients);
        can_unfollow = 1;
    } else {
        can_unfollow = 0;
    }

    if (can_unfollow) {
        // Perform the unfollow operation
        printf("%s no longer has %s as a follower\n", followed_user->username, caller->username);
        printf("%s unfollows %s\n", caller->username, followed_user->username);
        remove_following(caller, followed_user);
        remove_follower(followed_user, caller);

    } else {
        // If username is not active client, do not execute the operation
        notify_client(caller, "The username you typed is not an active user\r\n");
    }
    free(name);
}


void process_show(struct client *caller) {
    int tmp_num_message;
    char tmp_message[BUF_SIZE];

    // For each user that caller is following
    for (int i = 0; i < caller->num_following; i++) {
        tmp_num_message = (caller->following[i])->num_messages;

        // For each message of the user that caller is following
        for (int j = 0; j < tmp_num_message; j++) {
            strcpy(tmp_message, (caller->following[i])->username);
            strcat(tmp_message, " wrote: ");
            strcat(tmp_message, (caller->following[i])->message[j]);
            notify_client(caller, tmp_message);
        }
    }
}


void process_send(struct client *caller) {
    // Checks whether the send command can be performed
    if (caller->num_messages == MSG_LIMIT) {
        notify_client(caller, "You have exceeded the maximum number of messages\r\n");

    } else {
        // Perform the send operation
        char final_message[BUF_SIZE];
        strcpy(final_message, caller->username);
        strcat(final_message, ": ");
        
        char *message = extract_message(caller->inbuf);

        strcpy(caller->message[caller->num_messages], message);
        strcat(caller->message[caller->num_messages], "\r\n");

        strcat(final_message, caller->message[caller->num_messages]);

        for (int i = 0; i < caller->num_followers; i++) {
            notify_client((caller->followers)[i], final_message);
        }
        caller->num_messages += 1;
        free(message);
    }
}

void emit_goodbye_message(struct client *leaver, struct client **active_clients) {
    struct client *p;
    char message[BUF_SIZE];
    strcpy(message, "Goodbye ");
    strcat(message, leaver->username);
    strcat(message, "\r\n");

    for (p = *active_clients; p != NULL; p = p->next) {    
        notify_client(p, message);
    }
    
}

void cancel_follows_disconnect(struct client *disconnected_user) {
    char name[BUF_SIZE];
    for (int i = 0; i < disconnected_user->num_followers; i++) {
        strcpy(name, (disconnected_user->followers[i])->username);
        printf("%s is no longer following %s because they disconnected\n", name, disconnected_user->username);
        printf("%s no longer has %s as a follower\n", disconnected_user->username, name);
    }
}

                                            


int main (int argc, char **argv) {
    int clientfd, maxfd, nready;
    struct client *p;
    struct sockaddr_in q;
    fd_set rset;

    // If the server writes to a socket that has been closed, the SIGPIPE
    // signal is sent and the process is terminated. To prevent the server
    // from terminating, ignore the SIGPIPE signal. 
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    // A list of active clients (who have already entered their names). 
    struct client *active_clients = NULL;

    // A list of clients who have not yet entered their names. This list is
    // kept separate from the list of active clients, because until a client
    // has entered their name, they should not issue commands or 
    // or receive announcements. 
    struct client *new_clients = NULL;

    struct sockaddr_in *server = init_server_addr(PORT);
    int listenfd = set_up_server_socket(server, LISTEN_SIZE);

    // Initialize allset and add listenfd to the set of file descriptors
    // passed into select 
    FD_ZERO(&allset);
    FD_SET(listenfd, &allset);

    // maxfd identifies how far into the set to search
    maxfd = listenfd;

    while (1) {
        // make a copy of the set before we pass it into select
        rset = allset;

        nready = select(maxfd + 1, &rset, NULL, NULL, NULL);
        if (nready == -1) {
            perror("select");
            exit(1);
        } else if (nready == 0) {
            continue;
        }

        // check if a new client is connecting
        if (FD_ISSET(listenfd, &rset)) {
            printf("A new client is connecting\n");
            clientfd = accept_connection(listenfd, &q);

            FD_SET(clientfd, &allset);
            if (clientfd > maxfd) {
                maxfd = clientfd;
            }
            printf("Connection from %s\n", inet_ntoa(q.sin_addr));
            add_client(&new_clients, clientfd, q.sin_addr);
            char *greeting = WELCOME_MSG;
            if (write(clientfd, greeting, strlen(greeting)) == -1) {
                fprintf(stderr, "Write to client %s failed\n", inet_ntoa(q.sin_addr));
                remove_client(&new_clients, clientfd);
            }
        }

        // Check which other socket descriptors have something ready to read.
        // The reason we iterate over the rset descriptors at the top level and
        // search through the two lists of clients each time is that it is
        // possible that a client will be removed in the middle of one of the
        // operations. This is also why we call break after handling the input.
        // If a client has been removed, the loop variables may no longer be 
        // valid.
        int cur_fd, handled;
        int nbytes, where;

        for (cur_fd = 0; cur_fd <= maxfd; cur_fd++) {
            if (FD_ISSET(cur_fd, &rset)) {
                handled = 0;

                // Check if any new clients are entering their names
                for (p = new_clients; p != NULL; p = p->next) {
                    
                    if (cur_fd == p->fd) {

                        nbytes = read(cur_fd, p->in_ptr, BUF_SIZE);

                        if (nbytes == -1) {
                            perror("read");
                            exit(1);
                        }
                        
                        printf("[%d] Read %d bytes\n", cur_fd, nbytes);

                        if (nbytes == 0) { // If write socket is closed or disconnected
                            emit_goodbye_message(p, &active_clients);
                            printf("Disconnect from %s\n", inet_ntoa(q.sin_addr));
                            cancel_follows_disconnect(p);
                            remove_client(&active_clients, cur_fd);
                            break;
                        }

                        p->in_ptr = p->in_ptr + nbytes;
                        where = find_network_newline(p, 0);

                        if (where > 0) {

                            // If acceptable username is typed
                            if (strlen(p->inbuf) != 0 && username_exists(p->inbuf, &active_clients) == NULL) {

                                // Store the buffer into username
                                int name_length = strlen(p->inbuf);
                                strcpy(p->username, p->inbuf);
                                p->username[name_length] = '\0';

                                // Initialize p->inbuf, p->in_ptr for future use in reading commands
                                p->inbuf[0] = '\0';
                                p->in_ptr = p->inbuf;

                                // While maintaining the info including username, remove user from new_clients and add it to active_clients
                                remove_client_from_new_list(&new_clients, cur_fd);
                                add_client_to_list(&active_clients, p);
                                
                                char message[BUF_SIZE];
                                strcpy(message, p->username);
                                strcat(message, " has just joined.\r\n");
                                printf("%s", message);

                                // Inform all active clients that a new user has joined
                                struct client *tmp_p;

                                for (tmp_p = active_clients; tmp_p != NULL; tmp_p = tmp_p->next) {
                                    if (write(tmp_p->fd, message, strlen(message)) == -1) {
                                        fprintf(stderr, "Write to client %s failed\n", inet_ntoa(q.sin_addr));
                                        remove_client(&new_clients, clientfd);
                                    }
                                }
                            
                            } else {
                                // If not acceptable username is typed
                                p->inbuf[0] = '\0';
                                p->in_ptr = p->inbuf;
                                
                                notify_client(p, "Invalid username or username already exists. Please type again\r\n");
                            }

                        }

                        handled = 1;
                        break;
                    }
                }

                if (!handled) {
                    // Check if this socket descriptor is an active client
                    for (p = active_clients; p != NULL; p = p->next) {
                        if (cur_fd == p->fd) {
                            
                            nbytes = read(cur_fd, p->in_ptr, BUF_SIZE);
                            if (nbytes == -1) {
                                perror("read");
                                exit(1);
                            }

                            printf("[%d] Read %d bytes\n", cur_fd, nbytes);
                            
                            if (nbytes == 0) { // If write socket is closed or disconnected
                                emit_goodbye_message(p, &active_clients);
                                printf("Disconnect from %s\n", inet_ntoa(q.sin_addr));
                                cancel_follows_disconnect(p);
                                remove_client(&active_clients, cur_fd);
                                break;
                            }

                            p->in_ptr = p->in_ptr + nbytes;
                            where = find_network_newline(p, 1);

                            if (where > 0) {

                                printf("%s: %s\n", p->username, p->inbuf);
                                int result = check_command(p->inbuf); // check the validity and the kind of command from input

                                if (result > 0) {    // If valid command,

                                    switch(result) {
                                        case 1: // follow command
                                            process_follow(p, &active_clients);
                                            p->inbuf[0] = '\0';
                                            p->in_ptr = p->inbuf;
                                            break;

                                        case 2: // unfollow command
                                            process_unfollow(p, &active_clients);
                                            p->inbuf[0] = '\0';
                                            p->in_ptr = p->inbuf;                                            
                                            break;

                                        case 3: // show command
                                            process_show(p);
                                            p->inbuf[0] = '\0';
                                            p->in_ptr = p->inbuf;
                                            break;

                                        case 4: // send command
                                            process_send(p);
                                            p->inbuf[0] = '\0';
                                            p->in_ptr = p->inbuf;
                                            break;

                                        case 5: // quit command
                                            // Close the socket connection and terminate.
                                            emit_goodbye_message(p, &active_clients);
                                            printf("Disconnect from %s\n", inet_ntoa(q.sin_addr));
                                            cancel_follows_disconnect(p);
                                            remove_client(&active_clients, cur_fd);
                                            break;

                                        default:
                                            // Cannot reach here
                                            break;
                                    }

                                } else { // If invalid command,
                                    printf("Invalid command\n");
                                    p->inbuf[0] = '\0';
                                    p->in_ptr = p->inbuf;

                                    notify_client(p, "Invalid command\r\n");
                                }

                            }

                            break;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

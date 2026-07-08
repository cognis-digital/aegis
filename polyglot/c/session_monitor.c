#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define MAX_SESSIONS 100
#define MAX_BUFFER 1024

typedef struct {
    int session_id;
    int socket_fd;
    char ip[INET6_ADDRSTRLEN];
    char user[256];
    int status; // 0: active, 1: closed
} Session;

Session sessions[MAX_SESSIONS];
int session_count = 0;

void log_session(int session_id, const char *message) {
    printf("[%d] %s\n", session_id, message);
}

void handle_client(int client_fd, int session_id) {
    char buffer[MAX_BUFFER];
    ssize_t bytes_read;

    log_session(session_id, "Client connected");

    while ((bytes_read = read(client_fd, buffer, MAX_BUFFER)) > 0) {
        buffer[bytes_read] = '\0';
        log_session(session_id, buffer);

        // Simulate injection check
        if (strstr(buffer, "..") || strstr(buffer, ";")) {
            log_session(session_id, "Potential injection detected");
        }

        // Simulate credential check
        if (strstr(buffer, "admin") && strstr(buffer, "password")) {
            log_session(session_id, "Credentials found in request");
        }

        // Simulate reach check (simulated as presence of 'root' or 'sudo')
        if (strstr(buffer, "root") || strstr(buffer, "sudo")) {
            log_session(session_id, "Potential elevated access detected");
        }
    }

    log_session(session_id, "Client disconnected");
    close(client_fd);
    sessions[session_id].status = 1;
}

void *session_monitor(void *arg) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    if (bind(server_fd, (struct sockaddr *)&address, addrlen) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    log_session(0, "Session monitor started on port 8080");

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue;
        }

        if (session_count >= MAX_SESSIONS) {
            log_session(0, "Max sessions reached, rejecting new connection");
            close(new_socket);
            continue;
        }

        sessions[session_count].session_id = session_count + 1;
        sessions[session_count].socket_fd = new_socket;
        getpeername(new_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        inet_ntop(AF_INET, &address.sin_addr, sessions[session_count].ip, INET6_ADDRSTRLEN);
        strcpy(sessions[session_count].user, "anonymous");
        sessions[session_count].status = 0;

        log_session(session_count + 1, "Session started from IP: ");
        log_session(session_count + 1, sessions[session_count].ip);

        pthread_t thread;
        if (pthread_create(&thread, NULL, (void *(*)(void *))handle_client, (void *)(intptr_t)new_socket) != 0) {
            perror("pthread_create");
            close(new_socket);
        } else {
            pthread_detach(thread);
        }

        session_count++;
    }

    return NULL;
}

int main() {
    pthread_t monitor_thread;

    if (pthread_create(&monitor_thread, NULL, session_monitor, NULL) != 0) {
        perror("pthread_create");
        exit(EXIT_FAILURE);
    }

    pthread_join(monitor_thread, NULL);

    return 0;
}
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SERVER_PORT 8080
#define BUF_SIZE 256
#define BUFFER_SIZE 1024


ssize_t write_fully(int fd, const void *buffer, size_t len);
ssize_t read_fully(int fd, void *buffer, size_t len);


int main(int argc, char *argv[])
{
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[BUF_SIZE];

    if (argc < 2)
    {
        printf("Usage: %s <server_ip>\n", argv[0]);
        return EXIT_FAILURE;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        perror("listening_socket");
        return EXIT_FAILURE;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, argv[1], &server_addr.sin_addr) <= 0)
    {
        perror("inet_pton");
        return EXIT_FAILURE;
    }

    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
    {
        perror("connect");
        return EXIT_FAILURE;
    }

    printf("Connected to server.\n");

    ssize_t n_user;

    while((n_user = read(STDIN_FILENO, buffer, BUF_SIZE)) > 0)
    {
        write_fully(sockfd, buffer, n_user);
        read_fully(sockfd, buffer, n_user);
    }

    close(sockfd);

    return EXIT_SUCCESS;
}

ssize_t write_fully(int fd, const void *buffer, size_t len)
{
    ssize_t total_bytes_write = 0;

    while (total_bytes_write < (ssize_t)len)
    {
        ssize_t bytes_write = write(fd, (const uint8_t *)buffer + total_bytes_write, len - total_bytes_write);

        if(bytes_write == -1)
        {
            perror("write");
            exit(EXIT_FAILURE); // NOLINT(concurrency-mt-unsafe)
        }

        total_bytes_write += bytes_write;
    }

    return total_bytes_write;
}

ssize_t read_fully(int fd, void *buffer, size_t len)
{
    char bb[BUFFER_SIZE];

    ssize_t valread = read(fd, bb, BUFFER_SIZE);
    if (valread < 0) {
        perror("webserver (read)");
        exit(-12);
    }
    printf("String %s \n", bb);

    return valread;
}
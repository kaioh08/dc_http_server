#include "../include/utility.h"
#include <arpa/inet.h>
#include <dc_c/dc_signal.h>
#include <dc_c/dc_stdio.h>
#include <dc_c/dc_stdlib.h>
#include <dc_c/dc_string.h>
#include <dc_env/env.h>
#include <dc_error/error.h>
#include <dc_posix/dc_poll.h>
#include <dc_posix/dc_unistd.h>
#include <dc_posix/sys/dc_socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <dc_posix/arpa/dc_inet.h>
#include <dc_util/networking.h>
#include <dlfcn.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <dc_util/io.h>

#define SERVER_PORT 5000
#define BACKLOG 10
#define MAX_CLIENTS 10
#define POLL_TIMEOUT (-1)
#define BUFFER_SIZE 1024

int flow = 0;

static void ctrl_c_handler(__attribute__((unused)) int signum);
static int setup_server(struct dc_env *env, struct dc_error *err);
static void run_server(struct dc_env *env, struct dc_error *err, int listener, int *client_sockets);
static void wait_for_data(struct dc_env *env, struct dc_error *err, int listener, const int *client_sockets, int num_clients, struct pollfd *fds);
static void handle_new_connections(struct dc_env *env, struct dc_error *err, int listener, int *client_sockets, int *num_clients, struct pollfd *fds);
static void handle_client_data(struct dc_env *env, struct dc_error *err, int *client_sockets, int *num_clients, struct pollfd *fds);


static volatile sig_atomic_t done = false;   // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)


int main(void)
{
    struct dc_env *env;
    struct dc_error *err;
    int listener;
    int client_sockets[MAX_CLIENTS];
    int ret_val;

    err = dc_error_create(true);
    env = dc_env_create(err, true, NULL);
    listener = setup_server(env, err);

    if(dc_error_has_no_error(err))
    {
        dc_signal(env, err, SIGINT, ctrl_c_handler);

        if(dc_error_has_no_error(err))
        {
            run_server(env, err, listener, client_sockets);
        }

        dc_close(env, err, listener);
    }

    if(dc_error_has_no_error(err))
    {
        ret_val = EXIT_SUCCESS;
    }
    else
    {
        fprintf(stderr, "ERROR %s\n", dc_error_get_message(err)); // NOLINT(cert-err33-c)
        ret_val = EXIT_FAILURE;
    }

    return ret_val;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void ctrl_c_handler(__attribute__((unused)) int signum)
{
    done = 1;
}
#pragma GCC diagnostic pop

static int setup_server(struct dc_env *env, struct dc_error *err)
{
    int listener;

    DC_TRACE(env);
    listener = dc_socket(env, err, AF_INET, SOCK_STREAM, 0);

    if(dc_error_has_no_error(err))
    {
        static int optval = 1;

        dc_setsockopt(env, err, listener, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

        if(dc_error_has_no_error(err))
        {
            struct sockaddr_in server_addr;

            dc_memset(env, &server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_addr.s_addr = dc_inet_addr(env, err, dc_get_ip_addresses_by_interface(env, err,  dc_get_default_interface(env, err, AF_INET), AF_INET));
            server_addr.sin_port = htons(SERVER_PORT);

            // Print out the IP address and port number
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(server_addr.sin_addr), ip_str, INET_ADDRSTRLEN);

            printf("IP Address: %s\n", ip_str);
            printf("Port: %d\n", ntohs(server_addr.sin_port));
            dc_bind(env, err, listener, (struct sockaddr*)&server_addr, sizeof(server_addr));

            if(dc_error_has_no_error(err))
            {
                dc_listen(env, err, listener, BACKLOG);
            }
        }
    }

    return listener;
}

static void run_server(struct dc_env *env, struct dc_error *err, int listener, int *client_sockets)
{
    struct pollfd fds[MAX_CLIENTS + 1];
    int num_clients;
    int i;

    DC_TRACE(env);

    num_clients = 0;

    for(i = 0; i < MAX_CLIENTS; i++)
    {
        client_sockets[i] = -1;
    }

    fds[0].fd = listener;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    while(!(done))
    {
        wait_for_data(env, err, listener, client_sockets, num_clients, fds);

        if(dc_error_has_no_error(err))
        {
            handle_new_connections(env, err, listener, client_sockets, &num_clients, fds);

            if(dc_error_has_no_error(err))
            {
                handle_client_data(env, err, client_sockets, &num_clients, fds);
            }
        }

        dc_error_reset(err);
    }
}

static void wait_for_data(struct dc_env *env, struct dc_error *err, int listener, const int *client_sockets, int num_clients, struct pollfd *fds)
{
    int i;

    DC_TRACE(env);

    fds[0].fd = listener;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    for (i = 0; i < num_clients; i++)
    {
        fds[i + 1].fd = client_sockets[i];
        fds[i + 1].events = POLLIN;
    }

    dc_poll(env, err, fds, num_clients + 1, POLL_TIMEOUT);
}

static void handle_new_connections(struct dc_env *env, struct dc_error *err, int listener, int *client_sockets, int *num_clients, struct pollfd *fds)
{
    int i;
    int new_socket;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len;

    DC_TRACE(env);
    client_addr_len = sizeof(client_addr);

    if((unsigned int)fds[0].revents & (unsigned int)POLLIN)
    {
        new_socket = dc_accept(env, err, listener, (struct sockaddr *)&client_addr, &client_addr_len);

        if(dc_error_has_no_error(err))
        {
            printf("New connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));    // NOLINT(concurrency-mt-unsafe)

            for(i = 0; i < MAX_CLIENTS; i++)
            {
                if(client_sockets[i] == -1)
                {
                    client_sockets[i] = new_socket;
                    break;
                }
            }

            if(i == MAX_CLIENTS)
            {
                printf("Too many clients, Will be dropping new incoming connection\n");
                close(new_socket);
                return;
            }

            fds[i + 1].fd = new_socket;
            fds[i + 1].events = POLLIN;
            (*num_clients)++;
        }
    }
}

static void handle_client_data(struct dc_env *env, struct dc_error *err, int *client_sockets, int * num_clients, struct pollfd *fds)
{
    DC_TRACE(env);

    for(int i = 0; i < * num_clients; i++)
    {
        if((unsigned int)fds[i + 1].revents & (unsigned int)POLLIN)
        {
            ssize_t bytes_read;
            char buffer[BUFFER_SIZE];

            bytes_read = dc_read(env, err, client_sockets[i], buffer, sizeof(buffer));

            if(bytes_read <= 0)
            {
                printf("Client disconnected\n");
                dc_close(env, err, client_sockets[i]);
                client_sockets[i] = -1;

                for(int j = i; j < (*num_clients) - 1; j++)
                {
                    client_sockets[j] = client_sockets[j + 1];
                    fds[j + 1] = fds[j + 2];
                }

                (*num_clients)--;
                i--;
                continue;
            }

            printf("Read from client\n");
            dc_write(env, err, STDOUT_FILENO, buffer, bytes_read);

            if (flow == 0) {
                char message[] = "201\3";
                send_create_user(env, err, client_sockets[i], message);
                flow++;
            } else if (flow == 1) {
                char message[1024];
                dc_strcpy(env, message, "200");
                dc_strcat(env, message, "\3");
                dc_strcat(env, message, "Wumbo");
                dc_strcat(env, message, "\3");
                dc_strcat(env, message, "0");
                dc_strcat(env, message, "\3");
                dc_strcat(env, message, "1");
                dc_strcat(env, message, "\3");
                dc_strcat(env, message, "GLOBAL_TEST");
                dc_strcat(env, message, "\3");
                send_create_auth(env, err, client_sockets[i], message);
                flow++;
            } else if (flow == 2) {
                char message[1024];
                dc_strcpy(env, message, "201");
                dc_strcat(env, message, "\3");
                send_create_channel(env, err, client_sockets[i], message);
                flow++;
            } else if (flow >= 3) {
                char message[1024];
                dc_strcpy(env, message, "200");
                dc_strcat(env, message, "\3");
                send_update_channel(env, err, client_sockets[i], message);
                if (flow == 3) {
                    flow++;
                } else {
                    flow = 0;
                }
            }
//            send_create_message(env, err, client_sockets[i], message);
        }
    }
}
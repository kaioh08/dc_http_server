#include <dc_c/dc_stdio.h>
#include <dc_c/dc_stdlib.h>
#include <dc_c/dc_string.h>
#include <dc_posix/arpa/dc_inet.h>
#include <dc_posix/dc_dlfcn.h>
#include <dc_posix/dc_poll.h>
#include <dc_posix/dc_semaphore.h>
#include <dc_posix/dc_signal.h>
#include <dc_posix/dc_string.h>
#include <dc_posix/dc_unistd.h>
#include <dc_posix/sys/dc_select.h>
#include <dc_posix/sys/dc_socket.h>
#include <dc_posix/sys/dc_wait.h>
#include <dc_unix/dc_getopt.h>
#include <dc_util/networking.h>
#include <dc_util/system.h>
#include <dc_util/types.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include "processes.h"
#include <sys/stat.h>
#include <dc_util/io.h>

typedef void (*read_message_func)(const struct dc_env *env, struct dc_error *err, uint8_t **raw_data, int client_socket, struct http_packet_info *packet_info);
typedef void (*process_message_func)(const struct dc_env *env, struct dc_error *err, struct http_packet_info * httpPacketInfo);
typedef void (*send_message_func)(const struct dc_env *env, struct dc_error *err, int client_socket, bool *closed, struct http_packet_info * httpPacketInfo);


struct settings
{
    char *library_path;
    char *interface; // ifconfig
    char *address; // ip address
    uint16_t port; // port
    uint16_t backlog; // number of backlog for listen
    uint8_t jobs; // jobs to create
    bool verbose_server;
    bool verbose_handler;
    bool debug_server;
    bool debug_handler;
};

struct server_info
{
    sem_t *domain_sem;
    int domain_socket;
    int pipe_fd;
    int num_workers;
    pid_t *workers;
    int listening_socket;
    int num_fds;
    struct pollfd *poll_fds;
};

struct message_handler
{
    read_message_func reader;
    process_message_func processor;
    send_message_func sender;
};

struct worker_info
{
    sem_t *select_sem;
    sem_t *domain_sem;
    int domain_socket;
    int pipe_fd;
    struct message_handler message_handler;
};

struct revive_message
{
    int fd;
    bool closed;
};


static void setup_default_settings(const struct dc_env *env, struct dc_error *err, struct settings *default_settings);
static void copy_settings(const struct dc_env *env, struct dc_error *err, struct settings *settings, const struct settings *default_settings);
static void print_settings(const struct dc_env *env, const struct settings *settings);
static void destroy_settings(const struct dc_env *env, struct settings *settings);
static bool parse_args(const struct dc_env *env, struct dc_error *err, int argc, char **argv, struct settings *settings);
static const char *check_settings(const struct dc_env *env, const struct settings *settings);
static void usage(const struct dc_env *env, const char *program_name, const struct settings *default_settings, const char *message);
static void sigint_handler(__attribute__((unused)) int signal);
static void setup_message_handler(const struct dc_env *env, struct dc_error *err, struct message_handler *message_handler, void *library);
static bool create_workers(struct dc_env *env, struct dc_error *err, const struct settings *settings, pid_t *workers, sem_t *select_sem, sem_t *domain_sem, const int domain_sockets[2], const int pipe_fds[2]);
static void initialize_server(const struct dc_env *env, struct dc_error *err, struct server_info *server,  const struct settings *settings, sem_t *domain_sem, int domain_socket, int pipe_fd, pid_t *workers);
static void destroy_server(const struct dc_env *env, struct dc_error *err, struct server_info *server);
static void run_server(const struct dc_env *env, struct dc_error *err, struct server_info *server, const struct settings *settings);
static void server_loop(const struct dc_env *env, struct dc_error *err, const struct settings *settings, struct server_info *server);
static bool handle_change(const struct dc_env *env, struct dc_error *err, const struct settings *settings, struct server_info *server, struct pollfd *poll_fd);
static void accept_connection(const struct dc_env *env, struct dc_error *err, const struct settings *settings, struct server_info *server);
static void write_socket_to_domain_socket(const struct dc_env *env, struct dc_error *err, const struct settings *settings, const struct server_info *server, int client_socket);
static void revive_socket(const struct dc_env *env, struct dc_error *err, const struct settings *settings, const struct server_info *server, struct revive_message *message);
static void close_connection(const struct dc_env *env, struct dc_error *err, const struct settings *settings, struct server_info *server, int client_socket);
static void wait_for_workers(const struct dc_env *env, struct dc_error *err, struct server_info *server);
static void worker_process(struct dc_env *env, struct dc_error *err, struct worker_info *worker, const struct settings *settings);
static bool extract_message_parameters(const struct dc_env *env, struct dc_error *err, struct worker_info *worker, int *client_socket, int *value);
static void process_message(const struct dc_env *env, struct dc_error *err, struct worker_info *worker, const struct settings *settings);
static void send_revive(const struct dc_env *env, struct dc_error *err, struct worker_info *worker, int client_socket, int fd, bool closed);
static void print_fd(const struct dc_env *env, const char *message, int fd, bool display);
static void print_socket(const struct dc_env *env, struct dc_error *err, const char *message, int socket, bool display);

//char * get_http_time(const struct dc_env *env, struct dc_error *err);
//void read_message_handler(const struct dc_env *env, struct dc_error *err, uint8_t **raw_data, int client_socket, struct http_packet_info * httpPacketInfo);
//void process_message_handler(const struct dc_env *env, struct dc_error *err, struct http_packet_info * httpPacketInfo);
//void send_message_handler(const struct dc_env *env, struct dc_error *err, int client_socket, bool *closed, struct http_packet_info * httpPacketInfo);



static const int DEFAULT_N_PROCESSES = 2;
static const int DEFAULT_PORT = 80;
static const int DEFAULT_BACKLOG = SOMAXCONN;
static volatile sig_atomic_t done = 0;     // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static const char * const READ_MESSAGE_FUNC = "read_message_handler";
static const char * const PROCESS_MESSAGE_FUNC = "process_message_handler";
static const char * const SEND_MESSAGE_FUNC = "send_message_handler";

int main(int argc, char *argv[])
{
    struct dc_error *err;
    struct dc_env *env;
    dc_env_tracer tracer;
    bool should_exit;
    struct settings *default_settings;
    struct settings settings;
    const char *error_message;
//    tracer = dc_env_default_tracer; // Trace through function calls
    tracer = NULL; // Don't trace through function calls
    err = dc_error_create(false);
    env = dc_env_create(err, true, tracer);
    default_settings = dc_malloc(env, err, sizeof(*default_settings));
    setup_default_settings(env, err, default_settings);
    dc_memset(env, &settings, 0, sizeof(settings));
    copy_settings(env, err, &settings, default_settings);
    should_exit = parse_args(env, err, argc, argv, &settings);

    if(!(should_exit))
    {
        error_message = check_settings(env, &settings);

        if(error_message != NULL)
        {
            should_exit = true;
        }
    }
    else
    {
        error_message = NULL;
    }

    if(should_exit)
    {
        usage(env, argv[0], default_settings, error_message);
        destroy_settings(env, default_settings);
        dc_free(env, default_settings);
    }
    else
    {
        sem_t *select_sem;
        sem_t *domain_sem;
        int domain_sockets[2];
        int pipe_fds[2];
        pid_t *workers;
        bool is_server;
        pid_t pid;
        char domain_sem_name[100];  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        char select_sem_name[100];  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

        if(settings.debug_server)
        {
            dc_env_set_tracer(env, dc_env_default_tracer);
        }

        destroy_settings(env, default_settings);
        dc_free(env, default_settings);

        socketpair(AF_UNIX, SOCK_DGRAM, 0, domain_sockets);
        dc_pipe(env, err, pipe_fds);
        printf("Starting server (%d) on %s:%d\n", getpid(), settings.address, settings.port);
        print_settings(env, &settings);
        workers = NULL;
        pid = getpid();
        sprintf(domain_sem_name, "/sem-%d-domain", pid);    // NOLINT(cert-err33-c)
        sprintf(select_sem_name, "/sem-%d-select", pid);    // NOLINT(cert-err33-c)
        select_sem = sem_open(select_sem_name, O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, 1);
        domain_sem = sem_open(domain_sem_name, O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, 1);
        workers = (pid_t *)dc_malloc(env, err, settings.jobs * sizeof(pid_t));
        is_server = create_workers(env, err, &settings, workers, select_sem, domain_sem, domain_sockets, pipe_fds);

        if(is_server)
        {
            struct sigaction act;
            struct server_info server;

            act.sa_handler = sigint_handler;
            dc_sigemptyset(env, err, &act.sa_mask);
            act.sa_flags = 0;
            dc_sigaction(env, err, SIGINT, &act, NULL);
            dc_close(env, err, domain_sockets[0]);
            dc_close(env, err, pipe_fds[1]);
            dc_memset(env, &server, 0, sizeof(server));
            initialize_server(env, err, &server, &settings, domain_sem, domain_sockets[1], pipe_fds[0], workers);
            run_server(env, err, &server, &settings);
            destroy_server(env, err, &server);
        }

        sem_close(domain_sem);
        sem_close(select_sem);

        if(is_server)
        {
            sem_unlink(domain_sem_name);
            sem_unlink(select_sem_name);
        }
    }

    destroy_settings(env, &settings);
    printf("Exiting %d\n", getpid());
    free(env);
    dc_error_reset(err);
    free(err);

    return EXIT_SUCCESS;
}

static void setup_default_settings(const struct dc_env *env, struct dc_error *err, struct settings *default_settings)
{
    DC_TRACE(env);
    default_settings->library_path     = NULL;
    default_settings->interface        = dc_get_default_interface(env, err, AF_INET);
    default_settings->address          = dc_get_ip_addresses_by_interface(env, err, default_settings->interface, AF_INET);
    default_settings->port             = DEFAULT_PORT;
    default_settings->backlog          = DEFAULT_BACKLOG;
    default_settings->jobs             = dc_get_number_of_processors(env, err, DEFAULT_N_PROCESSES);
    default_settings->verbose_server   = false;
    default_settings->verbose_handler  = false;
    default_settings->debug_server     = false;
    default_settings->debug_handler    = false;
}

static void copy_settings(const struct dc_env *env, struct dc_error *err, struct settings *settings, const struct settings *default_settings)
{
    DC_TRACE(env);
    settings->interface        = dc_strdup(env, err, default_settings->interface);
    settings->address          = dc_strdup(env, err, default_settings->address);
    settings->port             = default_settings->port;
    settings->backlog          = default_settings->backlog;
    settings->jobs             = default_settings->jobs;
    settings->verbose_server   = default_settings->verbose_server;
    settings->verbose_handler  = default_settings->verbose_handler;
    settings->debug_server     = default_settings->debug_server;
    settings->debug_handler    = default_settings->debug_handler;
}

static void print_settings(const struct dc_env *env, const struct settings *settings)
{
    DC_TRACE(env);
    // NOLINTBEGIN(cert-err33-c)
    fprintf(stderr, "\tLibrary:            %s\n",  settings->library_path);
    fprintf(stderr, "\tNetwork interface:  %s\n",  settings->interface);
    fprintf(stderr, "\tIP address:         %s\n",  settings->address);
    fprintf(stderr, "\tPort number:        %d\n",  settings->port);
    fprintf(stderr, "\tBacklog size:       %d\n",  settings->backlog);
    fprintf(stderr, "\tNumber of handlers: %d\n",  settings->jobs);
    fprintf(stderr, "\tVerbose server:     %s\n",  settings->verbose_server == true ? "on" : "off");
    fprintf(stderr, "\tVerbose handler:    %s\n",  settings->verbose_handler == true ? "on" : "off");
    fprintf(stderr, "\tVerbose server:     %s\n",  settings->debug_server == true ? "on" : "off");
    fprintf(stderr, "\tVerbose handler:    %s\n",  settings->debug_handler == true ? "on" : "off");
    // NOLINTEND(cert-err33-c)
}

static void destroy_settings(const struct dc_env *env, struct settings *settings)
{
    DC_TRACE(env);

    if(settings->library_path)
    {
        dc_free(env, settings->library_path);
    }

    if(settings->interface)
    {
        dc_free(env, settings->interface);
    }

    if(settings->address)
    {
        dc_free(env, settings->address);
    }
}

static bool parse_args(const struct dc_env *env, struct dc_error *err, int argc, char **argv, struct settings *settings)
{
    static const int base = 10;
    static struct option long_options[] =
            {
                    {"library-path", required_argument, 0, 'l'},
                    {"interface", required_argument, 0, 'i'},
                    {"address", required_argument, 0, 'a'},
                    {"port", required_argument, 0, 'p'},
                    {"backlog", required_argument, 0, 'b'},
                    {"jobs", required_argument, 0, 'j'},
                    {"buffer-size", required_argument, 0, 's'},
                    {"timeout-seconds", required_argument, 0, 'T'},
                    {"timeout-nseconds", required_argument, 0, 't'},
                    {"verbose-server", no_argument, 0, 'v'},
                    {"verbose-handler", no_argument, 0, 'V'},
                    {"debug-server", no_argument, 0, 'd'},
                    {"debug-handler", no_argument, 0, 'D'},
                    {"help", no_argument, 0, 'h'},
                    {0, 0, 0, 0}
            };
    int opt;
    int option_index;
    bool should_exit;

    DC_TRACE(env);
    option_index = 0;
    should_exit = false;

    while((opt = dc_getopt_long(env, argc, argv, "l:i:a:p:b:j:vVdDh", long_options, &option_index)) != -1)
    {
        switch (opt)
        {
            case 'l':
                settings->library_path = dc_strdup(env, err, optarg);
                break;
            case 'i':
                settings->interface = dc_strdup(env, err, optarg);
                break;
            case 'a':
                settings->address = dc_strdup(env, err, optarg);
                break;
            case 'p':
                settings->port = dc_uint16_from_str(env, err, optarg, base);
                break;
            case 'b':
                settings->backlog = dc_uint16_from_str(env, err, optarg, base);
                break;
            case 'j':
                settings->jobs = dc_uint8_from_str(env, err, optarg, base);
                break;
            case 'v':
                settings->verbose_server = true;
                break;
            case 'V':
                settings->verbose_handler = true;
                break;
            case 'd':
                settings->debug_server = true;
                break;
            case 'D':
                settings->debug_handler = true;
                break;
            case 'h':
                should_exit = true;
            default:
                break;
        }
    }

    return should_exit;
}

static const char *check_settings(const struct dc_env *env, const struct settings *settings)
{
    const char *message;

    DC_TRACE(env);

    if(settings->library_path == NULL)
    {
        message = "library-path argument missing";
    }
    else
    {
        message = NULL;
    }

    return message;
}

static void usage(const struct dc_env *env, const char *program_name, const struct settings *default_settings, const char *message)
{
    DC_TRACE(env);
    // NOLINTBEGIN(cert-err33-c)
    if(message != NULL)
    {
        fprintf(stderr, "%s\n", message);
    }

    fprintf(stderr, "Usage: %s [options]\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "\t-l, --Library_path          Library (default: %s)\n", default_settings->library_path);
    fprintf(stderr, "\t-i, --Interface        Network interface (default: %s)\n", default_settings->interface);
    fprintf(stderr, "\t-a, --Address          IP address (default: %s)\n", default_settings->address);
    fprintf(stderr, "\t-p, --Port             Port number (default: %d)\n", default_settings->port);
    fprintf(stderr, "\t-b, --Backlog          Backlog size (default: %d)\n", default_settings->backlog);
    fprintf(stderr, "\t-j, --Jobs             Number of handlers (default: %d)\n", default_settings->jobs);
    fprintf(stderr, "\t-v, --Verbose-server   Verbose server (default: %s)\n", default_settings->verbose_server == true ? "on" : "off");
    fprintf(stderr, "\t-V, --Verbose-handler  Verbose handler (default: %s)\n", default_settings->verbose_handler == true ? "on" : "off");
    fprintf(stderr, "\t-v, --Debug-server     Debug server (default: %s)\n", default_settings->debug_server == true ? "on" : "off");
    fprintf(stderr, "\t-V, --Debug-handler    Debug handler (default: %s)\n", default_settings->debug_handler == true ? "on" : "off");
    fprintf(stderr, "\t-h, --Help             Display this help message\n");
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void sigint_handler(__attribute__((unused)) int signal)
{
    done = true;
}
#pragma GCC diagnostic pop


static void setup_message_handler(const struct dc_env *env, struct dc_error *err, struct message_handler *message_handler, void *library)
{
    read_message_func    read_func;
    process_message_func process_func;
    send_message_func    send_func;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    read_func = (read_message_func)dc_dlsym(env, err, library, READ_MESSAGE_FUNC);
#pragma GCC diagnostic pop

    if(dc_error_has_no_error(err))
    {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
        process_func = (process_message_func) dc_dlsym(env, err, library, PROCESS_MESSAGE_FUNC);
#pragma GCC diagnostic pop

        if(dc_error_has_no_error(err))
        {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
            send_func = (send_message_func)dc_dlsym(env, err, library, SEND_MESSAGE_FUNC);
#pragma GCC diagnostic pop

            if(dc_error_has_no_error(err))
            {
                message_handler->reader = read_func;
                message_handler->processor = process_func;
                message_handler->sender = send_func;
            }
        }
    }
}


static bool create_workers(struct dc_env *env, struct dc_error *err, const struct settings *settings, pid_t *workers, sem_t *select_sem, sem_t *domain_sem, const int domain_sockets[2], const int pipe_fds[2])
{
    DC_TRACE(env);


    for(int i = 0; i < settings->jobs; i++)
    {
        pid_t pid;

        pid = dc_fork(env, err);

        if(pid == 0)
        {
            struct sigaction act;
            struct worker_info worker;
            void *library;

            act.sa_handler = sigint_handler;
            dc_sigemptyset(env, err, &act.sa_mask);
            act.sa_flags = 0;
            dc_sigaction(env, err, SIGINT, &act, NULL);
            dc_free(env, workers);
            dc_close(env, err, domain_sockets[1]);
            dc_close(env, err, pipe_fds[0]);
            library = dc_dlopen(env, err, settings->library_path, RTLD_LAZY);

            if(dc_error_has_no_error(err))
            {
                dc_memset(env, &worker.message_handler, 0, sizeof(worker.message_handler));
                setup_message_handler(env, err, &worker.message_handler, library);
                worker.select_sem = select_sem;
                worker.domain_sem = domain_sem;
                worker.domain_socket = domain_sockets[0];
                worker.pipe_fd = pipe_fds[1];
                worker_process(env, err, &worker, settings);
                dc_dlclose(env, err, library);
            }

            return false;
        }

        workers[i] = pid;
    }

    return true;
}

static void initialize_server(const struct dc_env *env, struct dc_error *err, struct server_info *server,  const struct settings *settings, sem_t *domain_sem, int domain_socket, int pipe_fd, pid_t *workers)
{
    static int optval = 1;
    struct sockaddr_in server_address;

    DC_TRACE(env);
    server->domain_sem = domain_sem;
    server->domain_socket = domain_socket;
    server->pipe_fd = pipe_fd;
    server->num_workers = settings->jobs;
    server->workers = workers;
    server->listening_socket = socket(AF_INET, SOCK_STREAM, 0);
    dc_memset(env, &server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = dc_inet_addr(env, err, settings->address);
    server_address.sin_port = dc_htons(env, settings->port);
    dc_setsockopt(env, err, server->listening_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    dc_bind(env, err, server->listening_socket, (struct sockaddr *)&server_address, sizeof(server_address));
    dc_listen(env, err, server->listening_socket, settings->backlog);
    server->poll_fds = (struct pollfd *)dc_malloc(env, err, sizeof(struct pollfd) * 2);
    server->poll_fds[0].fd = server->listening_socket;
    server->poll_fds[0].events = POLLIN;
    server->poll_fds[1].fd = server->pipe_fd;
    server->poll_fds[1].events = POLLIN;
    server->num_fds = 2;
}

static void destroy_server(const struct dc_env *env, struct dc_error *err, struct server_info *server)
{
    if(server->poll_fds)
    {
        dc_free(env, server->poll_fds);
    }

    if(server->workers)
    {
        dc_free(env, server->workers);
    }

    dc_close(env, err, server->domain_socket);
    dc_close(env, err, server->pipe_fd);
}

static void run_server(const struct dc_env *env, struct dc_error *err, struct server_info *server, const struct settings *settings)
{
    DC_TRACE(env);
    server_loop(env, err, settings, server);
    wait_for_workers(env, err, server);
}

static void server_loop(const struct dc_env *env, struct dc_error *err, const struct settings *settings, struct server_info *server)
{
    DC_TRACE(env);

    while(!done)
    {
        int poll_result;

        poll_result = dc_poll(env, err, server->poll_fds, server->num_fds, -1);

        if(poll_result < 0)
        {
            break;
        }

        if(poll_result == 0)
        {
            continue;
        }

        // the increment only happens if the connection isn't closed, if it is closed everything moves down one spot.
        for(int i = 0; i < server->num_fds; i++)
        {
            struct pollfd *poll_fd;

            poll_fd = &server->poll_fds[i];

            if(poll_fd->revents != 0)
            {
                handle_change(env, err, settings, server, poll_fd);
            }
        }

        if(dc_error_has_error(err))
        {
            done = true;
        }
    }
}

static bool handle_change(const struct dc_env *env, struct dc_error *err, const struct settings *settings, struct server_info *server, struct pollfd *poll_fd)
{
    int fd;
    short revents;
    int close_fd;

    DC_TRACE(env);
    fd = poll_fd->fd;
    revents = poll_fd->revents;
    close_fd = -1;

    if((unsigned int)revents & (unsigned int)POLLHUP)
    {
        if(fd != server->listening_socket && fd != server->pipe_fd)
        {
            close_fd = fd;
        }
    }
    else if((unsigned int)revents & (unsigned int)POLLIN)
    {
        if(fd == server->listening_socket)
        {
            accept_connection(env, err, settings, server);
        }
        else if(fd == server->pipe_fd)
        {
            struct revive_message message;

            revive_socket(env, err, settings, server, &message);

            if(message.closed)
            {
                close_fd = message.fd;
            }
        }
        else
        {
            poll_fd->events = 0;
            write_socket_to_domain_socket(env, err, settings, server, fd);
        }
    }

    if(close_fd > -1)
    {
        close_connection(env, err, settings, server, close_fd);
    }

    return close_fd != -1;
}

static void accept_connection(const struct dc_env *env, struct dc_error *err, const struct settings *settings, struct server_info *server)
{
    struct sockaddr_in client_address;
    socklen_t client_address_len;
    int client_socket;

    DC_TRACE(env);
    client_address_len = sizeof(client_address);
    client_socket = dc_accept(env, err, server->listening_socket, (struct sockaddr *)&client_address, &client_address_len);
    server->poll_fds = (struct pollfd *)dc_realloc(env, err, server->poll_fds, (server->num_fds + 2) * sizeof(struct pollfd));
    server->poll_fds[server->num_fds].fd = client_socket;
    server->poll_fds[server->num_fds].events = POLLIN | POLLHUP;
    server->poll_fds[server->num_fds].revents = 0;
    server->num_fds++;
    print_socket(env, err, "Accepted connection from", client_socket, settings->verbose_server);
}

static void write_socket_to_domain_socket(const struct dc_env *env, struct dc_error *err, const struct settings *settings, const struct server_info *server, int client_socket)
{
    struct msghdr msg;
    struct iovec iov;
    char control_buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;

    DC_TRACE(env);
    dc_memset(env, &msg, 0, sizeof(msg));
    dc_memset(env, &iov, 0, sizeof(iov));
    dc_memset(env, control_buf, 0, sizeof(control_buf));
    iov.iov_base = &client_socket;
    iov.iov_len = sizeof(client_socket);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf;
    msg.msg_controllen = sizeof(control_buf);
    cmsg = CMSG_FIRSTHDR(&msg);

    if(cmsg)
    {
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        *((int *) CMSG_DATA(cmsg)) = client_socket;
        print_fd(env, "Sending to client", client_socket, settings->verbose_server);

        // Send the client listening_socket descriptor to the domain listening_socket
        dc_sendmsg(env, err, server->domain_socket, &msg, 0);
    }
    else
    {
        char *error_message;
        error_message = dc_strerror(env, err, errno);
        DC_ERROR_RAISE_SYSTEM(err, error_message, errno);
    }
}

static void revive_socket(const struct dc_env *env, struct dc_error *err, const struct settings *settings, const struct server_info *server, struct revive_message *message)
{
    DC_TRACE(env);

    dc_sem_wait(env, err, server->domain_sem);
    dc_read(env, err, server->pipe_fd, message, sizeof(*message));
    dc_sem_post(env, err, server->domain_sem);

    if(dc_error_has_no_error(err))
    {
        print_fd(env, "Reviving listening_socket", message->fd, settings->verbose_server);

        for(int i = 2; i < server->num_fds; i++)
        {
            struct pollfd *pfd;

            pfd = &server->poll_fds[i];

            if(pfd->fd == message->fd)
            {
                pfd->events = POLLIN | POLLHUP;
            }
        }
    }
}

static void close_connection(const struct dc_env *env, struct dc_error *err, const struct settings *settings, struct server_info *server, int client_socket)
{
    DC_TRACE(env);
    print_fd(env, "Closing", client_socket, settings->verbose_server);
    dc_close(env, err, client_socket);

    for(int i = 0; i < server->num_fds; i++)
    {
        if(server->poll_fds[i].fd == client_socket)
        {
            for(int j = i; j < server->num_fds - 1; j++)
            {
                server->poll_fds[j] = server->poll_fds[j + 1];
            }

            break;
        }
    }

    server->num_fds--;

    if(server->num_fds == 0)
    {
        free(server->poll_fds);
        server->poll_fds = NULL;
    }
    else
    {
        server->poll_fds = (struct pollfd *)realloc(server->poll_fds, server->num_fds * sizeof(struct pollfd));
    }
}

static void wait_for_workers(const struct dc_env *env, struct dc_error *err, struct server_info *server)
{
    DC_TRACE(env);

    // since the children have the signal handler too they will also be notified, no need to kill them
    for(int i = 0; i < server->num_workers; i++)
    {
        int status;

        do
        {
            dc_waitpid(env, err, server->workers[i], &status, WUNTRACED
                                                              #ifdef WCONTINUED
                                                              | WCONTINUED
#endif
            );
        }
        while (!WIFEXITED(status) && !WIFSIGNALED(status));
    }

    dc_close(env, err, server->listening_socket);
}

static void worker_process(struct dc_env *env, struct dc_error *err, struct worker_info *worker, const struct settings *settings)
{
    pid_t pid;

    DC_TRACE(env);

    if(settings->debug_handler)
    {
        dc_env_set_tracer(env, dc_env_default_tracer);
    }
    else
    {
        dc_env_set_tracer(env, NULL);
    }

    pid = dc_getpid(env);
    printf("Started Worker (%d)\n", pid);

    while(!done)
    {
        process_message(env, err, worker, settings);

        if(dc_error_has_error(err))
        {
            printf("%d : %s\n", getpid(), dc_error_get_message(err));
            dc_error_reset(err);
        }
    }

    dc_close(env, err, worker->domain_socket);
    dc_close(env, err, worker->pipe_fd);
}

static bool extract_message_parameters(const struct dc_env *env, struct dc_error *err, struct worker_info *worker, int *client_socket, int *value)
{
    struct msghdr msg;
    char buf[CMSG_SPACE(sizeof(int) * 2)];
    struct iovec io;
    struct cmsghdr *cmsg;
    fd_set read_fds;
    int result;
    bool got_message;

    DC_TRACE(env);
    dc_memset(env, &msg, 0, sizeof(msg));
    dc_memset(env, &io, 0, sizeof(io));
    dc_memset(env, buf, '\0', sizeof(buf));
    io.iov_base = value;
    io.iov_len = sizeof(*value);

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    FD_ZERO(&read_fds);
    FD_SET(worker->domain_socket, &read_fds);

    dc_sem_wait(env, err, worker->select_sem);

    if(done)
    {
        got_message = false;
    }
    else
    {
        result = dc_select(env, err, worker->domain_socket + 1, &read_fds, NULL, NULL, NULL);

        if(result > 0)
        {
            dc_recvmsg(env, err, worker->domain_socket, &msg, 0);
            got_message = true;
        }
        else
        {
            got_message = false;
        }

        dc_sem_post(env, err, worker->select_sem);

        if(got_message)
        {
            cmsg = CMSG_FIRSTHDR(&msg);
            (*client_socket) = *((int *) CMSG_DATA(cmsg));
        }
    }

    return got_message;
}

static void process_message(const struct dc_env *env, struct dc_error *err, struct worker_info *worker, const struct settings *settings)
{
    int client_socket;
    int fd;
    bool got_message;

    client_socket = -1;
    got_message = extract_message_parameters(env, err, worker, &client_socket, &fd);

    if(got_message && dc_error_has_no_error(err))
    {
        uint8_t *raw_data;
        struct http_packet_info packet_info;
        bool closed;

        print_fd(env, "Started working on", fd, settings->verbose_handler);
        dc_memset(env, &packet_info, 0, sizeof(packet_info));
        raw_data = NULL;
        worker->message_handler.reader(env, err, &raw_data, client_socket, &packet_info);
        closed = true; // set it to true so if the client forgets to set it the connection is closed which is probably bad for some things - making it noticed, also if there is an issue reading/writing probably should close.

        if(dc_error_has_no_error(err))
        {
            uint8_t *processed_data;

            processed_data = NULL;
            worker->message_handler.processor(env, err, &packet_info);

            if(dc_error_has_no_error(err))
            {
                worker->message_handler.sender(env, err, client_socket, &closed, &packet_info);
            }

            if(processed_data)
            {
                dc_free(env, processed_data);
            }
        }

        if(raw_data)
        {
            dc_free(env, raw_data);
        }

        print_fd(env, "Done working on", fd, settings->verbose_handler);
        send_revive(env, err, worker, client_socket, fd, closed);
    }
}

static void send_revive(const struct dc_env *env, struct dc_error *err, struct worker_info *worker, int client_socket, int fd, bool closed)
{
    struct revive_message message;

    DC_TRACE(env);
    dc_memset(env, &message, 0, sizeof(message));
    message.fd = fd;
    message.closed = closed;
    dc_sem_wait(env, err, worker->domain_sem);
    dc_write(env, err, worker->pipe_fd, &message, sizeof(message));
    dc_sem_post(env, err, worker->domain_sem);
    dc_close(env, err, client_socket);
}

static void print_fd(const struct dc_env *env, const char *message, int fd, bool display)
{
    DC_TRACE(env);

    if(display)
    {
        printf("(pid=%d) %s with FD %d\n", getpid(), message, fd);
    }
}

static void print_socket(const struct dc_env *env, struct dc_error *err, const char *message, int socket, bool display)
{
    DC_TRACE(env);

    if(display)
    {
        struct sockaddr_in peer_address;
        socklen_t peer_address_len;
        uint16_t port;
        char *printable_address;

        peer_address_len = sizeof(peer_address);
        dc_getpeername(env, err, socket, (struct sockaddr *)&peer_address, &peer_address_len);

        printable_address = dc_inet_ntoa(env, peer_address.sin_addr);
        port = dc_ntohs(env, peer_address.sin_port);
        printf("(pid=%d) %s: %s:%d - %d\n", getpid(), message, printable_address, port, socket);
    }
}
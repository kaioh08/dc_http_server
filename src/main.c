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
#include <sys/stat.h>
#include <dc_util/io.h>
#include <ndbm.h>

struct http_packet_info
{
    char* method;
    char* path;
    char* data;
    char* file_last_modified;
    char* if_modified_since;

    __off_t file_size;

    int read_fd;
    int is_conditional_get;
    int error;
};

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
static void setup_message_handler(struct message_handler *message_handler);
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

char * get_http_time(const struct dc_env *env, struct dc_error *err);
void read_message_handler(const struct dc_env *env, struct dc_error *err, uint8_t **raw_data, int client_socket, struct http_packet_info * httpPacketInfo);
void process_message_handler(const struct dc_env *env, struct dc_error *err, struct http_packet_info * httpPacketInfo);
void send_message_handler(const struct dc_env *env, struct dc_error *err, int client_socket, bool *closed, struct http_packet_info * httpPacketInfo);



static const int DEFAULT_N_PROCESSES = 2;
static const int DEFAULT_PORT = 8080;
static const int DEFAULT_BACKLOG = SOMAXCONN;
static const int BLOCK_SIZE = 1024 * 4;
static volatile sig_atomic_t done = 0;     // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)


int main(int argc, char *argv[])
{
    struct dc_error *err;
    struct dc_env *env;
    dc_env_tracer tracer;
    bool should_exit;
    struct settings *default_settings;
    struct settings settings;
    const char *error_message;


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
    if(message != NULL)
    {
        fprintf(stderr, "%s\n", message);
    }

    fprintf(stderr, "Usage: %s [options]\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "\t-l, --library_path     Library (default: %s)\n", default_settings->library_path);
    fprintf(stderr, "\t-i, --interface        Network interface (default: %s)\n", default_settings->interface);
    fprintf(stderr, "\t-a, --address          IP address (default: %s)\n", default_settings->address);
    fprintf(stderr, "\t-p, --port             Port number (default: %d)\n", default_settings->port);
    fprintf(stderr, "\t-b, --backlog          Backlog size (default: %d)\n", default_settings->backlog);
    fprintf(stderr, "\t-j, --jobs             Number of handlers (default: %d)\n", default_settings->jobs);
    fprintf(stderr, "\t-v, --verbose-server   Verbose server (default: %s)\n", default_settings->verbose_server == true ? "on" : "off");
    fprintf(stderr, "\t-V, --verbose-handler  Verbose handler (default: %s)\n", default_settings->verbose_handler == true ? "on" : "off");
    fprintf(stderr, "\t-v, --debug-server     Debug server (default: %s)\n", default_settings->debug_server == true ? "on" : "off");
    fprintf(stderr, "\t-V, --debug-handler    Debug handler (default: %s)\n", default_settings->debug_handler == true ? "on" : "off");
    fprintf(stderr, "\t-h, --help             Display this help message\n");
    // NOLINTEND(cert-err33-c)
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void sigint_handler(__attribute__((unused)) int signal)
{
    done = true;
}
#pragma GCC diagnostic pop

static void setup_message_handler(struct message_handler *message_handler)
{
    message_handler->reader = read_message_handler;
    message_handler->processor = process_message_handler;
    message_handler->sender = send_message_handler;
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
                setup_message_handler(&worker.message_handler);

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

        // the increment only happens if the connection isn't closed.
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
    print_fd(env, "Closing connection", client_socket, settings->verbose_server);
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
    printf("Started worker (%d)\n", pid);

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
        closed = true; // set it to true so if the client forgets to set it the connection
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
/**
 * Get the method from the request
*/
void get_method (const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info, char *raw_data);
/**
 * Get the path from the request
 */
void get_path (const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info, char *raw_data);
/**
 * Tries to open the file requested and stores the status value into the response packet
 */
void open_file(const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info);
/**
 * Creates a 404 packet to send to the client
 */
char * create_404_packet(const struct dc_env *env, struct dc_error *err);
/**
 * Creates the header to send to the client
*/
char * send_header_information(const struct dc_env *env, struct dc_error *err, struct http_packet_info * httpPacketInfo, const char * status_code_message);
/**
 * Copies the content within from_fd to to_fd of count bytes
*/
void copy(int from_fd, int to_fd, size_t count);
/**
 * Creates a 400 packet to send to the client
*/
char * create_bad_request_packet(const struct dc_env *env, struct dc_error *err);
/**
 * Sends the GET response to the client
*/
void send_get_response(const struct dc_env *env, struct dc_error *err, int client_socket, struct http_packet_info *httpPacketInfo);
/**
 * Sends the HEAD response to the client
*/
void send_head_response(const struct dc_env *env, struct dc_error *err, int client_socket, struct http_packet_info *httpPacketInfo);
/**
 * Gets the last modified time of the file
*/
char * get_last_modified_time(const struct dc_env *env, struct dc_error *err, const struct http_packet_info *httpPacketInfo);
char * head_create_404_packet(const struct dc_env *env, struct dc_error *err);
void check_if_modified_since(const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info, char *raw_data);
void send_get(const struct dc_env *env, struct dc_error *err, int client_socket, struct http_packet_info *httpPacketInfo);

#define BUFFER_SIZE 1024

typedef struct {
    uint32_t id;
    char *name;
} Object;
int save_object(struct dc_env* env, struct dc_error* err, DBM* db, Object* object);
int load_object(struct dc_env* env, struct dc_error* err, DBM* db, uint32_t id, Object** object);

void read_message_handler(const struct dc_env *env, struct dc_error *err, uint8_t **raw_data, int client_socket, struct http_packet_info * httpPacketInfo)
{
    DC_TRACE(env);
    ssize_t bytes_read;
    size_t buffer_len;
    char *buffer;

    buffer_len = BLOCK_SIZE * sizeof(buffer);
    buffer = dc_malloc(env, err, buffer_len);
    bytes_read = dc_read(env, err, client_socket, buffer, buffer_len);

    if(dc_error_has_no_error(err))
    {
        *raw_data = dc_malloc(env, err, bytes_read);
        dc_memcpy(env, *raw_data, buffer, bytes_read);
    }
    else
    {
        *raw_data = NULL;
    }
    httpPacketInfo->data = dc_malloc(env, err, bytes_read);
    httpPacketInfo->data = dc_strdup(env, err, buffer);
    dc_free(env, buffer);
}

void get_path (const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info, char *raw_data) {
    char *token;

    // tokenize the line using whitespace as the delimiter
    token = dc_strtok(env, raw_data, " ");

    // iterate through the tokens until the desired string is found
    while (token != NULL) {
        if (dc_strstr(env, token, "/") != NULL) {
            packet_info->path = dc_malloc(env, err, dc_strlen(env, token));
            packet_info->path = token;
            break;
        }
        token = dc_strtok(env, NULL, " ");
    }
}

void get_method (const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info, char *raw_data) {
    // Get the method of the request
    //  Example: GET /x HTTP/1.0
    char * method = dc_strtok(env, raw_data, " ");
    packet_info->method = dc_malloc(env, err, dc_strlen(env, method));
    packet_info->method = method;
}

void check_if_modified_since(const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info, char *raw_data) {
    char *token;

    // tokenize the line using whitespace as the delimiter
    token = dc_strtok(env, raw_data, " ");

    // iterate through the tokens until the desired string is found
    while (token != NULL) {
        if (dc_strstr(env, token, "If-Modified-Since") != NULL) {
            packet_info->is_conditional_get = 1;

            // Get the time stamp
            token = dc_strtok(env, NULL, "\r\n");
            packet_info->if_modified_since = dc_malloc(env, err, dc_strlen(env, token));
            packet_info->if_modified_since = token;
            break;
        }
        token = dc_strtok(env, NULL, " ");
    }
}

void open_file(const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info) {
    // Check if path is only /
    if (dc_strcmp(env, packet_info->path, "/") == 0) {
        // try and open index.html and send that back
        packet_info->read_fd = open("index.html", O_RDWR);
        packet_info->path = dc_strdup(env, err, "index.html");
    } else {
        // If not append . before and try to open file
        char * relative_path;
        relative_path = dc_calloc(env, err, 1, (dc_strlen(env, packet_info->path) + 2));
        dc_strcat(env, relative_path, ".");
        dc_strcat(env, relative_path, packet_info->path);
        dc_strcat(env, relative_path, "\0");
        packet_info->read_fd = open(relative_path, O_RDWR);
        packet_info->path = dc_strdup(env, err, relative_path);
        dc_free(env, relative_path);
    }
    // Get file information
    if (packet_info->read_fd) {
        struct stat st;
        stat(packet_info->path, &st);

        time_t last_modified = st.st_mtime;         // Get last modified time
        struct tm *time_info = gmtime(&last_modified);
        char buffer[BUFFER_SIZE];
        strftime(buffer, BUFFER_SIZE, "%a, %d %b %Y %H:%M:%S %Z\r\n", time_info);
        packet_info->file_last_modified = dc_strdup(env, err, buffer);

        __off_t size = st.st_size; // Get file size
        packet_info->file_size = size;
    }
}

void process_message_handler(const struct dc_env *env, struct dc_error *err, struct http_packet_info * httpPacketInfo)
{
    DC_TRACE(env);

    printf("String \n%s \n", httpPacketInfo->data);

    // Setup packet info and process the HTTP message Check the method of the request
    get_method(env, err, httpPacketInfo, dc_strdup(env, err, httpPacketInfo->data));

    if (dc_strcmp(env, httpPacketInfo->method, "GET") == 0 || dc_strcmp(env, httpPacketInfo->method, "HEAD") == 0) {
        get_path(env, err, httpPacketInfo,dc_strdup(env, err, httpPacketInfo->data));
        check_if_modified_since(env, err, httpPacketInfo, dc_strdup(env, err, httpPacketInfo->data));
        open_file(env, err, httpPacketInfo);
    } else if (dc_strcmp(env, httpPacketInfo->method, "POST") == 0) {
        // Process POST request here but not done !!!!!!!!!!!!!!!!!!!!!
    } else {
        // Not a valid method
        httpPacketInfo->error = 1;
    }
}

char * get_http_time(const struct dc_env *env, struct dc_error *err) {
    // Get current time
    char time_stamp[BUFFER_SIZE];
    time_t now = time(0);
    struct tm tm = *gmtime(&now);
    strftime(time_stamp, sizeof time_stamp, "%a, %d %b %Y %H:%M:%S %Z\r\n", &tm);

    // Format time into HTTP format
    char date[BUFFER_SIZE] = "";
    dc_strcat(env, date,  "Date: ");
    dc_strcat(env, date, time_stamp);

    // Return date
    return dc_strdup(env, err, date);
}

char * get_last_modified_time(const struct dc_env *env, struct dc_error *err, const struct http_packet_info *httpPacketInfo)
{
    // Format time into HTTP format
    char date[BUFFER_SIZE] = "";
    dc_strcat(env, date,  "Last-Modified: ");
    dc_strcat(env, date, httpPacketInfo->file_last_modified);

    // Return date
    return dc_strdup(env, err, date);
}

char * create_bad_request_packet(const struct dc_env *env, struct dc_error *err) {
    char * http_time = get_http_time(env, err);
    char data[BUFFER_SIZE] = "";
    dc_strcat(env, data,  "HTTP/1.0 400 BAD REQUEST\r\n");
    dc_strcat(env, data,  http_time);
    dc_strcat(env, data,  "Allow: GET, HEAD, POST\r\n");
    dc_strcat(env, data,  "Server: webserver-c\r\n");
    dc_strcat(env, data,  "Content-Type: text/html\r\n\r\n");
    dc_strcat(env, data,  "<html>400 BAD REQUEST, ONLY SUPPORTS HTTP 1.0 FUNCTIONS (GET, HEAD, POST)</html>\r\n");

    dc_free(env, http_time);
    return dc_strdup(env, err, data);
}

char * create_404_packet(const struct dc_env *env, struct dc_error *err) {
    char * http_time = get_http_time(env, err);
    char data[BUFFER_SIZE] = "";
    dc_strcat(env, data,  "HTTP/1.0 404 NOT FOUND\r\n");
    dc_strcat(env, data,  http_time);
    dc_strcat(env, data,  "Allow: GET, HEAD, POST\r\n");
    dc_strcat(env, data,  "Server: webserver-c\r\n");
    dc_strcat(env, data,  "Content-Type: text/html\r\n\r\n");
    dc_strcat(env, data,  "<html>404 NOT FOUND</html>\r\n");

    dc_free(env, http_time);
    return dc_strdup(env, err, data);
}
char * head_create_404_packet(const struct dc_env *env, struct dc_error *err) {
    char * http_time = get_http_time(env, err);
    char data[BUFFER_SIZE] = "";
    dc_strcat(env, data,  "HTTP/1.0 404 NOT FOUND\r\n");
    dc_strcat(env, data,  http_time);
    dc_strcat(env, data,  "Allow: GET, HEAD, POST\r\n");
    dc_strcat(env, data,  "Server: webserver-c\r\n");
    dc_strcat(env, data,  "Content-Type: text/html\r\n\r\n");

    dc_free(env, http_time);
    return dc_strdup(env, err, data);
}

void copy(int from_fd, int to_fd, size_t count)
{
    char *buffer;
    ssize_t rbytes;

    buffer = malloc(count);

    if(buffer == NULL)
    {
        fprintf(stderr, "Malloc Failed\n");
        return;
    }

    while((rbytes = read(from_fd, buffer, count)) > 0)
    {
        ssize_t wbytes;

        wbytes = write(to_fd, buffer, rbytes);

        if(wbytes == -1)
        {
            fprintf(stderr, "File Write Error\n");
            return;
        }
    }

    if(rbytes == -1)
    {
        fprintf(stderr, "File Read Error\n");
        return;
    }
    free(buffer);
}

char * send_header_information(const struct dc_env *env, struct dc_error *err, struct http_packet_info * httpPacketInfo, const char * status_code_message)
{
    char * last_modified_time = get_last_modified_time(env, err, httpPacketInfo);

    // Convert file size to string
    char * http_time = get_http_time(env, err);
    char str[20] = "";
    snprintf(str, sizeof(str), "%lld", (long long) httpPacketInfo->file_size);  // Convert the off_t value to a string

    // Create packet
    char data[BUFFER_SIZE] = "";
    dc_strcat(env, data,  "HTTP/1.0 ");
    dc_strcat(env, data,  status_code_message);
    dc_strcat(env, data,  "\r\n");
    dc_strcat(env, data,  http_time);
    dc_strcat(env, data,  "Server: webserver-c\r\n");
    dc_strcat(env, data,  last_modified_time);
    dc_strcat(env, data,  "Content-Length: ");
    dc_strcat(env, data,  str);
    dc_strcat(env, data,  "\r\n");
    dc_strcat(env, data,  "Content-Type: */*\r\n\r\n");
    printf("RESP: \n%s", data);

    dc_free(env, http_time);
    return dc_strdup(env, err, data);
}

void send_get(const struct dc_env *env, struct dc_error *err, int client_socket, struct http_packet_info *httpPacketInfo) {
    // Send file
    char * data = send_header_information(env, err, httpPacketInfo, "200 OK");
    dc_write_fully(env, err, client_socket, data, dc_strlen(env, data));
    copy(httpPacketInfo->read_fd, client_socket, httpPacketInfo->file_size);
    dc_write_fully(env, err, client_socket, "\r\n", 2);
    dc_free(env, data);

}

void send_get_response(const struct dc_env *env, struct dc_error *err, int client_socket, struct http_packet_info *httpPacketInfo) {
    // Check if request is conditional
    if (httpPacketInfo->is_conditional_get)
    {
        struct tm tm1, tm2;
        time_t t1, t2;

        // Parse the timestamps into struct tm format
        if (strptime(httpPacketInfo->if_modified_since, "%a, %d %b %Y %H:%M:%S GMT", &tm1) == NULL) {
            fprintf(stderr, "Invalid timestamp format: %s\n", httpPacketInfo->if_modified_since);
            return;
        }
        printf("IS MOD: %s \n", httpPacketInfo->file_last_modified);
        if (strptime(httpPacketInfo->file_last_modified, "%a, %d %b %Y %H:%M:%S GMT", &tm2) == NULL) {
            fprintf(stderr, "Invalid timestamp format: %s\n", get_last_modified_time(env, err, httpPacketInfo));
            return;
        }

        // Convert the timestamps to time_t format
        t1 = mktime(&tm1);
        t2 = mktime(&tm2);

        // If not modified since request date send 304
        // Compare the timestamps
        if (t2 > t1)
        {
            send_get(env, err, client_socket, httpPacketInfo);
        } else if (t1 > t2)
        {
            char * data = send_header_information(env, err, httpPacketInfo, "304 NOT MODIFIED");
            dc_write_fully(env, err, client_socket, data, dc_strlen(env, data));
            dc_write_fully(env, err, client_socket, "\r\n", 2);
            dc_free(env, data);
            return;
        } else
        {
            char * data = head_create_404_packet(env, err);
            dc_write_fully(env, err, client_socket, data, dc_strlen(env, data));
            dc_free(env, data);
            return;
        }
    } else
    {
        send_get(env, err, client_socket, httpPacketInfo);
    }
}

void send_head_response(const struct dc_env *env, struct dc_error *err, int client_socket, struct http_packet_info *httpPacketInfo)
{
    // Send header information
    char * data = send_header_information(env, err, httpPacketInfo, "200 OK");
    dc_write_fully(env, err, client_socket, data, dc_strlen(env, data));
    dc_write_fully(env, err, client_socket, "\r\n", 2);
    dc_free(env, data);
}

void send_message_handler(const struct dc_env *env, struct dc_error *err, int client_socket, bool *closed, struct http_packet_info * httpPacketInfo)
{
    DC_TRACE(env);

    if (httpPacketInfo->error == 1)
    {
        printf("BAD REQUEST, NOT (GET, POST, HEAD)\n");
        // Send bad request packet
        char *data = create_bad_request_packet(env, err);
        dc_write_fully(env, err, client_socket, data, dc_strlen(env, data));
        dc_free(env, data);
    }
    // If file not found
    if (httpPacketInfo->read_fd == -1) {
        printf("NOT FOUND\n");
        // Send 404 packet
        if (dc_strcmp(env, httpPacketInfo->method, "HEAD") == 0) {
            char * data = head_create_404_packet(env, err);
            dc_write_fully(env, err, client_socket, data, dc_strlen(env, data));
            dc_free(env, data);
            return;
        } else {
            char * data = create_404_packet(env, err);
            dc_write_fully(env, err, client_socket, data, dc_strlen(env, data));
            dc_free(env, data);
        }
    } else {
        // Check if request is GET
        if (dc_strcmp(env, httpPacketInfo->method, "GET") == 0)   {
            send_get_response(env, err, client_socket, httpPacketInfo);
        } else if (dc_strcmp(env, httpPacketInfo->method, "HEAD") == 0) {
            send_head_response(env, err, client_socket, httpPacketInfo);
        }
    }

    // Free memory
    dc_free(env, httpPacketInfo->method);
    dc_free(env, httpPacketInfo->path);
    dc_free(env, httpPacketInfo->data);
    close(httpPacketInfo->read_fd);

    *closed = true;
}

int save_object(struct dc_env* env, struct dc_error* err, DBM* db, Object* object){
    int error = -1;
    // serializing the struct into a binary val
    size_t size = sizeof(object->id) + dc_strlen(env, object->name) + 1;
    uint8_t* buffer = malloc(size);
    if (!buffer){
        fprintf(stderr, "failed to allocate memory in save_object()\n");
        return error;
    }

    uint32_t id = htonl(object->id);
    dc_memcpy(env, buffer, &id, sizeof(object->id));
    // don't really know if we need name or not
    dc_strcpy(env, (char*)buffer + sizeof(uint32_t), object->name);
    datum k, v;
    k.dptr = (char *)&object->id;
    k.dsize = sizeof(object->id);
    v.dptr = buffer;
    v.dsize = size;

    // store the struct in the database
    if (dbm_store(db, k , v, DBM_REPLACE) != 0){
        fprintf(stderr, "failed to store struct struct [save_object()]\n");
        free(buffer);
        return error;
    }

    free(buffer);
    return 0;
}

int load_object(struct dc_env* env, struct dc_error* err, DBM* db, uint32_t id, Object** object){
    int error = -1;
    // retrieve the struct from the db
    datum k = {(char*)&id, sizeof(uint32_t)};
    datum v = dbm_fetch(db, k);
    if (v.dptr){
        // deserialize the binary value into a struct
        uint32_t unpacked_id = ntohl(*(uint32_t*)v.dptr);
        char* name = (char*)v.dptr + sizeof(uint32_t);
        *object = malloc(sizeof(Object));
        if (!*object){
            fprintf(stderr, "failed to allocate memory [load_object()]");
            free(v.dptr);
            return error;
        }
        (*object)->id = unpacked_id;
        (*object)->name = name;
        return 0;
    } else {
        fprintf(stderr, "key not found [load_object()]\n");
        return error;
    }
}

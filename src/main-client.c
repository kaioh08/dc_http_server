#include "../include/processes.h"
#include <dc_c/dc_stdio.h>
#include <dc_c/dc_stdlib.h>
#include <dc_c/dc_string.h>
#include <dc_posix/dc_string.h>
#include <dc_posix/dc_unistd.h>
#include <dc_util/networking.h>
#include <dc_util/system.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <dc_util/io.h>
#include <ctype.h>
#include <ndbm.h>


#define BUFFER_SIZE 1024
#define MAX_POST_SIZE 1024
static const int BLOCK_SIZE = 1024 * 4;

/**
 *  Structure of request Body
 */
typedef struct {
    char * key;
    char * value;
} Object;


/**
 * Copies the content within from_fd to to_fd of count bytes
*/
void copy(int from_fd, int to_fd, size_t count);
void get_method (const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info, char *raw_data);
void get_path (const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info, char *raw_data);
void open_file(const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info);
char * create_404_packet(const struct dc_env *env, struct dc_error *err);
char * send_header_information(const struct dc_env *env, struct dc_error *err, struct http_packet_info * httpPacketInfo, const char * status_code_message);
char * create_bad_request_packet(const struct dc_env *env, struct dc_error *err);
char * get_last_modified_time(const struct dc_env *env, struct dc_error *err, const struct http_packet_info *httpPacketInfo);
void check_if_modified_since(const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info, char *raw_data);
char * get_http_time(const struct dc_env *env, struct dc_error *err);
void get_content_length(const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info, char *raw_data);
void handle_conditional_get(const struct dc_env *env, struct dc_error *err, struct http_packet_info *httpPacketInfo);
int validate_list(const struct dc_env *env, char* list);
void connect_to_db(struct http_packet_info * httpPacketInfo);
void add_to_database(const struct dc_env *env, struct dc_error *err, struct http_packet_info * httpPacketInfo);
char * read_post_body(const struct dc_env *env, struct dc_error *err, struct http_packet_info * httpPacketInfo, char * data);
char * create_404_header_packet(const struct dc_env *env, struct dc_error *err);
char * create_201_packet(const struct dc_env *env, struct dc_error *err);
char * create_204_packet(const struct dc_env *env, struct dc_error *err);
void send_get_response(const struct dc_env *env, struct dc_error *err, int client_socket, struct http_packet_info *httpPacketInfo);
void send_head_response(const struct dc_env *env, struct dc_error *err, int client_socket, struct http_packet_info *httpPacketInfo);
void send_post_response(const struct dc_env *env, struct dc_error *err, int client_socket, struct http_packet_info *httpPacketInfo);
void save_object(const struct dc_env *env, DBM *db, Object *object);
Object * load_object(const struct dc_env *env, struct dc_error *err, DBM* db, char * id);

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
    buffer[bytes_read] = '\0';
    httpPacketInfo->data = dc_malloc(env, err, bytes_read);
    httpPacketInfo->data = dc_strdup(env, err, buffer);
    dc_free(env, buffer);
}

void get_content_length(const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info, char *raw_data) {
    char *token;

    // tokenize the line using whitespace as the delimiter
    token = dc_strtok(env, raw_data, "\r\n");

    // iterate through the tokens until the desired string is found
    while (token != NULL) {
        if (dc_strstr(env, token, "Content-Length") != NULL) {
            token += dc_strlen(env, "Content-Length: "); // Move past the "Content-Length: " string
            char * end;
            long num = dc_strtol(env, err, token, &end, 10);
            if (token == end) {
                printf("Error: invalid number\n");
                packet_info->error = 1;
            } else if (*end != '\0') {
                printf("Error: extra characters after number\n");
                packet_info->error = 1;
            } else {
                packet_info->content_length = num;
            }
            break;
        }
        token = dc_strtok(env, NULL, "\r\n");
    }
    if (packet_info->content_length < 0 || packet_info->error == 1 || packet_info->content_length > MAX_POST_SIZE) {
        packet_info->response_type = BAD_REQUEST;
        return;
    }
}

void get_path(const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info, char *raw_data) {
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

void get_method(const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info, char *raw_data) {
    // Get the method of the request
    //  Example: GET /x HTTP/1.0
    char * method = dc_strtok(env, raw_data, " ");
    packet_info->method = dc_malloc(env, err, dc_strlen(env, method));
    packet_info->method = method;
}

void handle_conditional_get(const struct dc_env *env, struct dc_error *err, struct http_packet_info *httpPacketInfo)
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
        httpPacketInfo->response_type = OK;
        return;
    } else if (t1 > t2)
    {
        httpPacketInfo->response_type = NOT_MODIFIED;
        return;
    } else
    {
        httpPacketInfo->response_type = NOT_FOUND;
        return;
    }
}

void check_if_modified_since(const struct dc_env *env, struct dc_error *err, struct http_packet_info *packet_info, char *raw_data) {
    char *token;
    // Ensure resource is there
    if (packet_info->response_type == NOT_FOUND) {
        return;
    }
    // tokenize the line using whitespace as the delimiter
    token = dc_strtok(env, raw_data, " ");

    // iterate through the tokens until the desired string is found
    while (token != NULL) {
        if (dc_strstr(env, token, "If-Modified-Since") != NULL) {

            // Get the time stamp
            token = dc_strtok(env, NULL, "\r\n");
            packet_info->if_modified_since = dc_malloc(env, err, dc_strlen(env, token));
            packet_info->if_modified_since = token;
            handle_conditional_get(env, err, packet_info);
            return;
        }
        token = dc_strtok(env, NULL, " ");
    }
    packet_info->response_type = OK;
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
    if (packet_info->read_fd > 0) {
        struct stat st;
        stat(packet_info->path, &st);

        // Get last modified time
        time_t last_modified = st.st_mtime;
        struct tm *time_info = gmtime(&last_modified);
        char buffer[BUFFER_SIZE];
        strftime(buffer, BUFFER_SIZE, "%a, %d %b %Y %H:%M:%S %Z\r\n", time_info);
        packet_info->file_last_modified = dc_strdup(env, err, buffer);

        // Get file size
        __off_t size = st.st_size;
        packet_info->file_size = size;
    } else {
        packet_info->response_type = NOT_FOUND;
    }
}

void connect_to_db(struct http_packet_info * httpPacketInfo) {
    // Create or open the database
    DBM * db = dbm_open("webdatabase", O_CREAT | O_RDWR, 0666);
    if (!db) {
        fprintf(stderr, "Failed to open database.\n");
    }
    httpPacketInfo->db = db;
}

int validate_list(const struct dc_env *env, char* list) {
    char* line = dc_strtok(env, list, "\n");  // Get the first line
    while (line != NULL) {
        size_t len = dc_strlen(env, line);
        if (len > 0 && line[len - 1] == '\r') {
            line[len - 1] = '\0';  // Remove the trailing '\r'
        }
        char* colon = dc_strchr(env, line, ':');
        if (colon == NULL || colon == line || colon == &line[len - 1]) {
            // Colon not found, or it's the first or last character in the line
            return 0;
        }
        line = dc_strtok(env, NULL, "\n");  // Get the next line
    }
    return 1;
}

void add_to_database(const struct dc_env *env, struct dc_error *err, struct http_packet_info * httpPacketInfo) {
    char * body = read_post_body(env, err, httpPacketInfo, dc_strdup(env, err, httpPacketInfo->data));

    if (httpPacketInfo->content_length <= 0)
    {
        httpPacketInfo->response_type = NO_CONTENT;
        return;
    } else if (httpPacketInfo->error == 1) {
        return;
    } else if (body == NULL || validate_list(env, dc_strdup(env, err, body)) == 0) {
        httpPacketInfo->response_type = BAD_REQUEST;
        return;
    }

    connect_to_db(httpPacketInfo);
    size_t len = dc_strlen(env, body);

    Object *objects = malloc(sizeof(Object));
    int count = 1;
    char *token = dc_strtok(env, body, "\n");

    while (token != NULL) {
        char *colon = dc_strchr(env, token, ':');
        size_t key_len = colon - token;
        objects = realloc(objects, sizeof(Object) * count);
        objects[count - 1].key = malloc(sizeof(char) * (key_len + 1));
        objects[count - 1].value = malloc(sizeof(char) * (len - key_len));

        dc_strncpy(env, objects[count - 1].key, token, key_len);
        objects[count - 1].key[key_len] = '\0';
        dc_strcpy(env, objects[count - 1].value, colon + 2);

        token = dc_strtok(env, NULL, "\n");
        count++;
    }

    printf("RESULTS FROM DATABASE\n");
    for (int i = 0; i < count - 1; i++) {
        save_object(env, httpPacketInfo->db, &objects[i]);
        Object * object = load_object(env, err, httpPacketInfo->db, objects[i].key);
        printf("Object %d: key=%s, value=%s\n", i, object->key, object->value);
        free(object->key);
        free(object->value);
        free(object);
    }

    for (int i = 0; i < count - 1; i++) {
        free(objects[i].key);
        free(objects[i].value);
    }
    free(objects);

    httpPacketInfo->response_type = CREATED;
    dbm_close(httpPacketInfo->db);
}

char * read_post_body(const struct dc_env *env, struct dc_error *err, struct http_packet_info * httpPacketInfo, char * data) {
    DC_TRACE(env);
    if (httpPacketInfo->content_length <= 0) {
        return NULL;
    }
    char *ptr = dc_strstr(env, data, "\r\n\r\n");
    if (ptr != NULL) {
        ptr += 4; // skip over the second \r\n
    } else {
        // handle error: end of header not found
        httpPacketInfo->error = 1;
        httpPacketInfo->response_type = BAD_REQUEST;
        return NULL;
    }
    return dc_strdup(env, err, ptr);
}

void process_message_handler(const struct dc_env *env, struct dc_error *err, struct http_packet_info * httpPacketInfo)
{
    DC_TRACE(env);

    printf("\n REQUEST \n%s \n", httpPacketInfo->data);

    // Setup packet info
    // Process the HTTP message

    // Check the method of the request
    get_method(env, err, httpPacketInfo, dc_strdup(env, err, httpPacketInfo->data));

    if (dc_strcmp(env, httpPacketInfo->method, "GET") == 0 || dc_strcmp(env, httpPacketInfo->method, "HEAD") == 0) {
        // Order Matters
        get_path(env, err, httpPacketInfo,dc_strdup(env, err, httpPacketInfo->data));
        open_file(env, err, httpPacketInfo);
        check_if_modified_since(env, err, httpPacketInfo, dc_strdup(env, err, httpPacketInfo->data));
    } else if (dc_strcmp(env, httpPacketInfo->method, "POST") == 0) {
        get_content_length(env, err, httpPacketInfo, dc_strdup(env, err, httpPacketInfo->data));
        printf("Content Length: %ld\n", httpPacketInfo->content_length);
        add_to_database(env, err, httpPacketInfo);
    } else {
        // Not a valid method
        httpPacketInfo->error = 1;
        httpPacketInfo->response_type = BAD_REQUEST;
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

char * create_404_header_packet(const struct dc_env *env, struct dc_error *err) {
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
char * create_201_packet(const struct dc_env *env, struct dc_error *err) {
    char * http_time = get_http_time(env, err);
    char data[BUFFER_SIZE] = "";
    dc_strcat(env, data,  "HTTP/1.0 201 CREATED\r\n");
    dc_strcat(env, data,  http_time);
    dc_strcat(env, data,  "Allow: GET, HEAD, POST\r\n");
    dc_strcat(env, data,  "Server: webserver-c\r\n");
    dc_strcat(env, data,  "Content-Type: text/html\r\n\r\n");
    dc_strcat(env, data,  "<html>Created Object</html>\r\n");

    dc_free(env, http_time);
    return dc_strdup(env, err, data);
}


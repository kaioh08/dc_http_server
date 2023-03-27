#ifndef MULTIPLEX_PROCESSES_H
#define MULTIPLEX_PROCESSES_H

#include <dc_env/env.h>
#include <dc_error/error.h>
#include <stdint.h>
#include <sys/types.h>
#include <ndbm.h>


enum response_type{
    OK = 200,
    CREATED = 201,
    NO_CONTENT = 204,
    NOT_MODIFIED = 304,
    BAD_REQUEST = 400,
    NOT_FOUND = 404,
};

struct http_packet_info
{
    DBM * db;

    char * method;
    char * path;
    char * data;
    char * file_last_modified;
    char * if_modified_since;

    __off_t file_size;
    long content_length;

    int read_fd;
    int error;
    enum response_type response_type;
};

void read_message_handler(const struct dc_env *env, struct dc_error *err, uint8_t **raw_data, int client_socket, struct http_packet_info * httpPacketInfo);
void process_message_handler(const struct dc_env *env, struct dc_error *err, struct http_packet_info * httpPacketInfo);
void send_message_handler(const struct dc_env *env, struct dc_error *err, int client_socket, bool *closed, struct http_packet_info * httpPacketInfo);


#endif //MULTIPLEX_PROCESSES_H

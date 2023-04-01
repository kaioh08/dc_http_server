#include "../include/utility.h"
#include <dc_c/dc_stdlib.h>
#include <dc_c/dc_string.h>
#include <dc_env/env.h>
#include <dc_error/error.h>
#include <dc_c/dc_stdio.h>
#include <netinet/in.h>
#include <dc_util/io.h>

void display_header(struct binary_header_field * header, const char * data)
{
    printf("DATA PACKET\n");
    printf("Packet version: %d\n", header->version);
    printf("Packet type:  0x%02X\n", header->type);
    printf("Packet object type: 0x%02X\n", header->object);
    printf("Packet body size: %d\n", header->body_size);
//    printf("Packet body: %s\n", data);
}

struct binary_header_field * deserialize_header(uint32_t value) {
    struct binary_header_field * header;
    value = ntohl(value);
    header = malloc(sizeof(struct binary_header_field));
    header->version = (value >> 28) & 0x0F;
    header->type = (value >> 24) & 0x0F;
    header->object = (value >> 16) & 0xFF;
    header->body_size = value & 0xFFFF;
    header->body_size = header->body_size;
    return header;
}

void serialize_header(struct dc_env *env, struct dc_error *err, struct binary_header_field * header, int fd,
                      const char * body)
{
    char * data = dc_malloc(env, err, (sizeof(uint32_t) + dc_strlen(env, body)));


    uint32_t packet = ((header->version & 0xF) << 28) | ((header->type & 0xF) << 24) |
                      ((header->object & 0xFF) << 16) | ((header->body_size) & 0xFFFF);

    packet = htonl(packet);
    // Copy the packet into the data buffer
    dc_memcpy(env, data, &packet, sizeof(uint32_t));

    // Add the body to the data buffer
    dc_memcpy(env, data + sizeof(uint32_t), body, header->body_size);

    dc_write_fully(env, err, fd, data, (sizeof(uint32_t) + dc_strlen(env, body)));
}

/**
 * PAIN
 */

/**
 * Send Create Stuff
 */
void send_create_user(struct dc_env *env, struct dc_error *err, int fd, const char * body) {
    DC_TRACE(env);

    // Create specific header
    struct binary_header_field header;
    header.version = DEFAULT_VERSION;
    header.type = CREATE;
    header.object = USER;
    header.body_size = dc_strlen(env, body);
    // Display the header
    display_header(&header, body);
    // Send the header
    serialize_header(env, err, &header, fd, body);
}

void send_create_channel(struct dc_env *env, struct dc_error *err, int fd, const char * body) {
    DC_TRACE(env);

    // Create specific header
    struct binary_header_field header;
    header.version = DEFAULT_VERSION;
    header.type = CREATE;
    header.object = CHANNEL;
    header.body_size = dc_strlen(env, body);
    // Display the header
    display_header(&header, body);
    // Send the header
    serialize_header(env, err, &header, fd, body);
}

void send_create_message(struct dc_env *env, struct dc_error *err, int fd, const char * body) {
    DC_TRACE(env);

    // Create specific header
    struct binary_header_field header;
    header.version = DEFAULT_VERSION;
    header.type = CREATE;
    header.object = MESSAGE;
    header.body_size = dc_strlen(env, body);
    // Display the header
    display_header(&header, body);
    // Send the header
    serialize_header(env, err, &header, fd, body);
}

void send_create_auth(struct dc_env *env, struct dc_error *err, int fd, const char * body) {
    DC_TRACE(env);

    // Create specific header
    struct binary_header_field header;
    header.version = DEFAULT_VERSION;
    header.type = CREATE;
    header.object = AUTH;
    header.body_size = dc_strlen(env, body);
    // Display the header
    display_header(&header, body);
    // Send the header
    serialize_header(env, err, &header, fd, body);
}

/**
 * Send Read Stuff
 */
void send_read_user(struct dc_env *env, struct dc_error *err, int fd, const char * body) {
    DC_TRACE(env);

    // Create specific header
    struct binary_header_field header;
    header.version = DEFAULT_VERSION;
    header.type = READ;
    header.object = USER;
    header.body_size = dc_strlen(env, body);
    // Display the header
    display_header(&header, body);
    // Send the header
    serialize_header(env, err, &header, fd, body);
}

void send_read_channel(struct dc_env *env, struct dc_error *err, int fd, const char * body) {
    DC_TRACE(env);

    // Create specific header
    struct binary_header_field header;
    header.version = DEFAULT_VERSION;
    header.type = READ;
    header.object = CHANNEL;
    header.body_size = dc_strlen(env, body);
    // Display the header
    display_header(&header, body);
    // Send the header
    serialize_header(env, err, &header, fd, body);
}

void send_read_message(struct dc_env *env, struct dc_error *err, int fd, const char * body) {
    DC_TRACE(env);

    // Create specific header
    struct binary_header_field header;
    header.version = DEFAULT_VERSION;
    header.type = READ;
    header.object = MESSAGE;
    header.body_size = dc_strlen(env, body);
    // Display the header
    display_header(&header, body);
    // Send the header
    serialize_header(env, err, &header, fd, body);
}

/**
 * Send Update Stuff
 */
void send_update_user(struct dc_env *env, struct dc_error *err, int fd, const char * body) {
    DC_TRACE(env);

    // Create specific header
    struct binary_header_field header;
    header.version = DEFAULT_VERSION;
    header.type = UPDATE;
    header.object = USER;
    header.body_size = dc_strlen(env, body);
    // Display the header
    display_header(&header, body);
    // Send the header
    serialize_header(env, err, &header, fd, body);
}

void send_update_channel(struct dc_env *env, struct dc_error *err, int fd, const char * body) {
    DC_TRACE(env);

    // Create specific header
    struct binary_header_field header;
    header.version = DEFAULT_VERSION;
    header.type = UPDATE;
    header.object = CHANNEL;
    header.body_size = dc_strlen(env, body);
    // Display the header
    display_header(&header, body);
    // Send the header
    serialize_header(env, err, &header, fd, body);
}

void send_update_message(struct dc_env *env, struct dc_error *err, int fd, const char * body) {
    DC_TRACE(env);

    // Create specific header
    struct binary_header_field header;
    header.version = DEFAULT_VERSION;
    header.type = CREATE;
    header.object = MESSAGE;
    header.body_size = dc_strlen(env, body);
    // Display the header
    display_header(&header, body);
    // Send the header
    serialize_header(env, err, &header, fd, body);
}

void send_update_auth(struct dc_env *env, struct dc_error *err, int fd, const char * body) {
    DC_TRACE(env);

    // Create specific header
    struct binary_header_field header;
    header.version = DEFAULT_VERSION;
    header.type = CREATE;
    header.object = AUTH;
    header.body_size = dc_strlen(env, body);
    // Display the header
    display_header(&header, body);
    // Send the header
    serialize_header(env, err, &header, fd, body);
}

/**
 * Send Delete Stuff
 */
void send_delete_user(struct dc_env *env, struct dc_error *err, int fd, const char * body) {
    DC_TRACE(env);

    // Create specific header
    struct binary_header_field header;
    header.version = DEFAULT_VERSION;
    header.type = DESTROY;
    header.object = USER;
    header.body_size = dc_strlen(env, body);
    // Display the header
    display_header(&header, body);
    // Send the header
    serialize_header(env, err, &header, fd, body);
}

void send_delete_channel(struct dc_env *env, struct dc_error *err, int fd, const char * body) {
    DC_TRACE(env);

    // Create specific header
    struct binary_header_field header;
    header.version = DEFAULT_VERSION;
    header.type = DESTROY;
    header.object = CHANNEL;
    header.body_size = dc_strlen(env, body);
    // Display the header
    display_header(&header, body);
    // Send the header
    serialize_header(env, err, &header, fd, body);
}

void send_delete_message(struct dc_env *env, struct dc_error *err, int fd, const char * body) {
    DC_TRACE(env);

    // Create specific header
    struct binary_header_field header;
    header.version = DEFAULT_VERSION;
    header.type = DESTROY;
    header.object = MESSAGE;
    header.body_size = dc_strlen(env, body);
    // Display the header
    display_header(&header, body);
    // Send the header
    serialize_header(env, err, &header, fd, body);
}

void send_delete_auth(struct dc_env *env, struct dc_error *err, int fd, const char * body) {
    DC_TRACE(env);

    // Create specific header
    struct binary_header_field header;
    header.version = DEFAULT_VERSION;
    header.type = DESTROY;
    header.object = AUTH;
    header.body_size = dc_strlen(env, body);
    // Display the header
    display_header(&header, body);
    // Send the header
    serialize_header(env, err, &header, fd, body);
}






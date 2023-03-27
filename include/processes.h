

#ifndef DC_HTTP_SERVER_PROCESSES_H
#define DC_HTTP_SERVER_PROCESSES_H

#include <dc_env/env.h>
#include <dc_error/error.h>
#include <stdint.h>
#include <sys/types.h>


ssize_t read_message_handler(const struct dc_env *env, struct dc_error *err, uint8_t **raw_data, int client_socket);
size_t process_message_handler(const struct dc_env *env, struct dc_error *err, const uint8_t *raw_data, uint8_t **processed_data, ssize_t count);
void send_message_handler(const struct dc_env *env, struct dc_error *err, uint8_t *buffer, size_t count, int client_socket, bool *closed);

#endif //DC_HTTP_SERVER_PROCESSES_H

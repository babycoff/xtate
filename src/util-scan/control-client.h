#ifndef CONTROL_CLIENT_H
#define CONTROL_CLIENT_H
#include <stddef.h>
int control_client_request(const char *endpoint, const char *request,
                           char *response, size_t cap);
#endif

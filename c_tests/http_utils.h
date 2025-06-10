#ifndef HTTP_UTILS_H
#define HTTP_UTILS_H

#include <stdbool.h>
#include <stdint.h>

#define HTTP_UTILS_MAX_CHAR_ON_HOST 253
#define HTTP_UTILS_MAX_REQ_LENGTH 1023
#define HTTP_UTILS_STR_PORT_SIZE 6

typedef struct {
    char host[HTTP_UTILS_MAX_CHAR_ON_HOST + 1];
    char req[HTTP_UTILS_MAX_REQ_LENGTH + 1];
    char port[HTTP_UTILS_STR_PORT_SIZE];
    bool secured;
} http_utils_UrlSplitted;


#ifdef __cplusplus
extern "C"{
#endif

bool http_utils_parse_url(const char* url, http_utils_UrlSplitted* url_splitted);

#ifdef __cplusplus
}
#endif

#endif
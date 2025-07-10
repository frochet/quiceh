#include <stdlib.h>
#include <string.h>
#include "http_utils.h"

#define HTTP_UTILS_CHAR_IS_DIGIT(c) ((c) >= '0' && (c) <= '9')


static bool startswith(const char* str, const char* ref)
{
    while(*str != '\0' && *ref != '\0' && *ref == *str)
    {
        str++;
        ref++;
    }
    return *ref == '\0';
}

bool http_utils_parse_url(const char* url, http_utils_UrlSplitted* url_splitted)
{
    int i = 0;

    if(startswith(url, "https://"))
    {
        url_splitted->secured = true;
        strcpy(url_splitted->port, "443");
        url += 8;
    }
    else if(startswith(url, "http://"))
    {
        url_splitted->secured = false;
        strcpy(url_splitted->port, "80");
        url += 7;
    }
    else
    {
        return false;
    }


    // get the host from url
    i = 0;
    while(i < HTTP_UTILS_MAX_CHAR_ON_HOST && *url != '\0' && *url != '/' && *url != '?' && *url != '#' && *url != ':')
    {
        url_splitted->host[i] = *url;
        i++;
        url++;
    }
    url_splitted->host[i] = '\0';

    // get the port if it is specified
    if(*url == ':')
    {
        char port_str[HTTP_UTILS_STR_PORT_SIZE];
        i = 0;
        url++;
        while(i < HTTP_UTILS_STR_PORT_SIZE-1 && HTTP_UTILS_CHAR_IS_DIGIT(*url))
        {
            port_str[i] = *url;
            i++;
            url++;
        }
        port_str[i] = '\0';
        strcpy(url_splitted->port, port_str);
    }

    if(*url != '\0' && *url != '/' && *url != '?' && *url != '#' && *url != ':')
    {
        return false;
    }


    // get the relative url from url
    i = 0;
    while(i < HTTP_UTILS_MAX_REQ_LENGTH && *url != '\0' && *url != '#')
    {
        url_splitted->req[i] = *url;
        i++;
        url++;
    }
    if(i == 0)
    {
        // There is no relative url
        url_splitted->req[i] = '/';
        i++;
    }
    url_splitted->req[i] = '\0';

    if(*url != '\0' && *url != '#')
    {
        return false;
    }

    return true;
}
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "random.h"
#include "http_utils.h"
#include "quiceh.h"

#define MAX_DATAGRAM_SIZE 1350

#define HTTP_REQ_STREAM_ID 4

static bool set_blocking_mode(int fd, char blocking)
{
    if (fd < 0)
        return false;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return false;
    flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    return fcntl(fd, F_SETFL, flags) == 0;
}

static int bind_connect_addr(int fd, const struct addrinfo* hints, const char* name, const char* str_port, struct sockaddr* addr, socklen_t* addr_len, int (*func)(int, const struct sockaddr*, socklen_t))
{
    struct addrinfo* result = NULL;
    struct addrinfo* next_result = NULL;

    if(getaddrinfo(name, str_port, hints, &result))
    {
        fprintf(stderr, "Unable to find address\n");
        goto FREE;
    }

    next_result = result;

    while(next_result != NULL)
    {
        if (func(fd, next_result->ai_addr, next_result->ai_addrlen) == 0)
            break;

        next_result = next_result->ai_next;
    }

    if(next_result == NULL)
    {
        fprintf(stderr, "Connection refused\n");
        close(fd);
        fd = -1;
        goto FREE;
    }
    *addr = *(next_result->ai_addr);
    *addr_len = next_result->ai_addrlen;

FREE:
    freeaddrinfo(result);
    return fd;
}

static int build_socket(const char* local_hostname, char* str_local_port, const char* peer_hostname, char* str_peer_port, struct sockaddr* local, socklen_t* local_len, struct sockaddr* peer, socklen_t* peer_len)
{
    int fd;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = IPPROTO_UDP;

    fd = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol);
    if(fd == -1)
    {
        return -1;
    }

    fd = bind_connect_addr(fd, &hints, local_hostname, str_local_port, local, local_len, bind);
    if(fd == -1)
    {
        return -1;
    }

    fd = bind_connect_addr(fd, &hints, peer_hostname, str_peer_port, peer, peer_len, connect);

    return fd;
}



int main(int argc, char* argv[])
{
    http_utils_UrlSplitted url = {.host = "127.0.0.1", .port = "4433", .secured = true, .req = "/README.md"};
    bool req_sent = false;
    int return_code = 1;

    int fd = -1;
    ssize_t n;
    uint8_t buffer[65535] = {0};
    uint8_t out[MAX_DATAGRAM_SIZE] = {0};

    uint8_t scid[QUICEH_MAX_CONN_ID_LEN];
    struct sockaddr local, peer;
    socklen_t local_len, peer_len;

    quiceh_config* config = NULL;
    quiceh_conn* conn = NULL;
    quiceh_app_recv_buff_map* app_buffers = NULL;
    quiceh_stream_iter* stream_iter = NULL;

    if(argc > 1)
    {
        if(!http_utils_parse_url(argv[1], &url))
        {
            fprintf(stderr, "Invalid URL provided");
            goto FREE;
        }
    }


    fd = build_socket("0.0.0.0", "0", url.host, url.port, &local, &local_len, &peer, &peer_len);
    if(fd < 0)
    {
        goto FREE;
    }
    set_blocking_mode(fd, false);

    config = quiceh_config_new(QUICEH_PROTOCOL_VERSION);
    if(config == NULL)
    {
        goto FREE;
    }

    quiceh_config_verify_peer(config, false);

    const char* protos[] = {
        "hq-interop",
        "http/0.9",
        NULL
    };

    quiceh_config_set_application_protos(config, protos);

    quiceh_config_set_max_idle_timeout(config, 5000);
    quiceh_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiceh_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiceh_config_set_initial_max_data(config, 10000000);
    quiceh_config_set_initial_max_stream_data_bidi_local(config, 1000000);
    quiceh_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
    quiceh_config_set_initial_max_streams_bidi(config, 100);
    quiceh_config_set_initial_max_streams_uni(config, 100);
    quiceh_config_set_disable_active_migration(config, true);
    quiceh_config_set_active_connection_id_limit(config, 2);
    quiceh_config_set_max_connection_window(config, 25165824);
    quiceh_config_set_max_stream_window(config, 16777216);
    quiceh_config_set_cc_algorithm_name(config, "cubic");

    random_set_unsecure_seed(random_standard_seed());
    random_unsecure_bytes(scid, sizeof(scid));

    char ip_buf[INET_ADDRSTRLEN];
    printf("Local IP: %s:%d\n", inet_ntop(AF_INET, &((const struct sockaddr_in *)&local)->sin_addr, ip_buf, local_len), ntohs(((const struct sockaddr_in *)&local)->sin_port));

    printf("Peer IP: %s:%d\n", inet_ntop(AF_INET, &((const struct sockaddr_in *)&peer)->sin_addr, ip_buf, peer_len), ntohs(((const struct sockaddr_in *)&peer)->sin_port));

    conn = quiceh_connect(url.host, (uint8_t*)scid, sizeof(scid), &local, local_len, &peer, peer_len, config);
    if(conn == NULL)
    {
        goto FREE;
    }

    app_buffers = quiceh_app_recv_buf_map_default();
    if(app_buffers == NULL)
    {
        goto FREE;
    }

    quiceh_send_info out_info;

    n = quiceh_conn_send(conn, (uint8_t*)out, sizeof(out), &out_info);
    if(n < 0)
    {
        goto FREE;
    }
    printf("%ld, %ld\n", n, send(fd, out, n, 0));

    printf("first packet sent\n");

    struct pollfd pollfd[] = {{.fd = fd, .events = POLLIN}};

    while(!quiceh_conn_is_closed(conn))
    {
        int nfds = poll(pollfd, sizeof(pollfd) / sizeof(struct pollfd), quiceh_conn_timeout_as_millis(conn));
        if(nfds < 0)
        {
            perror("poll");
            goto FREE;
        }

        if(nfds == 0)
        {
            // timeout
            quiceh_conn_on_timeout(conn);
        }
        else
        {
            errno = 0;
            while(nfds > 0 && (n = recv(fd, buffer, sizeof(buffer), 0)) > 0)
            {
                quiceh_recv_info recv_info = {.from = &peer, .from_len = peer_len, .to = &local, .to_len = local_len};

                if(quiceh_conn_recv(conn, (uint8_t*)buffer, n, app_buffers, &recv_info) < 0)
                {
                    break;
                }
            }
            if(n < 0 && errno != 0 && errno != EWOULDBLOCK)
            {
                perror("recv");
                goto FREE;
            }
        }

        if(quiceh_conn_is_established(conn) && !req_sent)
        {
            fprintf(stderr, "Connected\n");
            char req[2048];
            uint64_t out_code;

            snprintf(req, sizeof(req), "GET %s\r\n", url.req);
            quiceh_conn_stream_send(conn, HTTP_REQ_STREAM_ID, (uint8_t*)req, strlen(req), true, &out_code);
            req_sent = true;
        }

        stream_iter = quiceh_conn_readable(conn);
        if(stream_iter == NULL)
        {
            fprintf(stderr, "quiceh_conn_readable error\n");
            goto FREE;
        }

        uint64_t stream_id;
        while((quiceh_stream_iter_next(stream_iter, &stream_id)))
        {
            bool fin = false;
            uint64_t error_code;
            if(quiceh_conn_version(conn) == QUICEH_PROTOCOL_VERSION_V1)
            {
                if((n = quiceh_conn_stream_recv(conn, stream_id, (uint8_t*)buffer, sizeof(buffer), &fin, &error_code)) < 0)
                {
                    fprintf(stderr, "quiceh_conn_stream_recv error\n");
                    goto FREE;
                }
                write(STDOUT_FILENO, buffer, n);
                if(fin)
                {
                    quiceh_conn_close(conn, true, 0x0, (uint8_t*)"kthxbye", 7);
                    break;
                }
            }
            else if(quiceh_conn_version(conn) == QUICEH_PROTOCOL_VERSION_VREVERSO)
            {
                const uint8_t* buf;
                if((n = quiceh_conn_stream_recv_v3(conn, stream_id, app_buffers, &buf, &fin, &error_code)) < 0)
                {
                    fprintf(stderr, "quiceh_conn_stream_recv error\n");
                    goto FREE;
                }
                write(STDOUT_FILENO, buf, n);
                quiceh_conn_stream_consumed(conn, stream_id, n, app_buffers);
                if(fin)
                {
                    quiceh_conn_close(conn, true, 0x0, (uint8_t*)"kthxbye", 7);
                    break;
                }
            }
            else
            {
                fprintf(stderr, "Unexpected conn version\n");
                goto FREE;
            }
        }

        while((n = quiceh_conn_send(conn, (uint8_t*)out, sizeof(out), &out_info)) > 0)
        {
            printf("send %ld, %ld\n", n, send(fd, out, n, 0));
        }
        if(n < 0 && n != QUICEH_ERR_DONE)
        {
            quiceh_conn_close(conn, false, 0x1, (uint8_t*)"fail", 4);
        }
    }


    return_code = 0;
FREE:
    quiceh_stream_iter_free(stream_iter);
    quiceh_app_recv_buf_map_free(app_buffers);
    quiceh_conn_free(conn);
    quiceh_config_free(config);
    if(fd >= 0)
    {
        close(fd);
    }

    return return_code;
}
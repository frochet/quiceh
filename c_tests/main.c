#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "random.h"
#include "quiceh.h"

#define MAX_DATAGRAM_SIZE 1350

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



int main()
{
    int return_code = 1;

    int fd = -1;
    int n;
    int32_t buffer[65535] = {0};
    uint8_t out[MAX_DATAGRAM_SIZE] = {0};

    uint8_t scid[QUICEH_MAX_CONN_ID_LEN];
    struct sockaddr local, peer;
    socklen_t local_len, peer_len;

    quiceh_config* config = NULL;
    quiceh_conn* conn = NULL;
    quiceh_app_recv_buff_map* app_buffers = NULL;
    quiceh_stream_iter* stream_iter = NULL;


    fd = build_socket("0.0.0.0", "0", "127.0.0.1", "4433", &local, &local_len, &peer, &peer_len);
    if(fd < 0)
    {
        goto FREE;
    }

    config = quiceh_config_new(QUICEH_PROTOCOL_VERSION);
    if(config == NULL)
    {
        goto FREE;
    }

    quiceh_config_verify_peer(config, false);

    uint8_t protos[] = "\x02h3" "\x0Ahq-interop" "\x08http/0.9";

    quiceh_config_set_application_protos(config, protos, sizeof(protos)-1);

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

    conn = quiceh_connect("127.0.0.1", (uint8_t*)scid, sizeof(scid), &local, local_len, &peer, peer_len, config);
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
    printf("%d, %ld\n", n, sendto(fd, out, n, 0, &peer, peer_len));

    printf("connected\n");

    while((n = recvfrom(fd, buffer, sizeof(buffer), 0, &peer, &peer_len)) > 0)
    {
        quiceh_recv_info recv_info = {.from = &peer, .from_len = peer_len, .to = &local, .to_len = local_len};

        printf("recv\n");

        if(quiceh_conn_recv(conn, (uint8_t*)buffer, n, app_buffers, &recv_info) < 0)
        {
            break;
        }
    }

    if(!quiceh_conn_is_established(conn))
    {
        goto FREE;
    }

    stream_iter = quiceh_conn_readable(conn);
    if(stream_iter == NULL)
    {
        goto FREE;
    }

    uint64_t stream_id;
    while((quiceh_stream_iter_next(stream_iter, &stream_id)))
    {
        bool fin = false;
        uint64_t error_code;
        if((n = quiceh_conn_stream_recv(conn, stream_id, (uint8_t*)buffer, sizeof(buffer), &fin, &error_code)) < 0)
        {
            goto FREE;
        }
        write(STDOUT_FILENO, buffer, n);
        if(fin)
        {
            break;
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
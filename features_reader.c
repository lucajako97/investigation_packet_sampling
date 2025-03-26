/*
To compile the eBPF program
clang -O2 -g -target bpf -c ringbuf_kern.c -o ringbuf_kern.o
bpftool prog load ringbuf_kern.o /sys/fs/bpf/my_prog
bpftool map pin name rb /sys/fs/bpf/my_ringbuf

docs: https://libbpf.readthedocs.io/en/latest/api.html
*/
#include </usr/src/linux-headers-6.8.0-52-generic/tools/bpf/resolve_btfids/libbpf/include/bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include </usr/src/linux-headers-6.8.0-52-generic/tools/bpf/resolve_btfids/libbpf/include/bpf/libbpf.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sched.h>

#define BPF_RINGBUF_MAP "packet_and_features_ring"

#define IP_ADDR_LEN_V4 4   //  4 bytes for IPv4
#define IP_ADDR_LEN_V6 16  // 16 bytes for IPv6

#define LAMBDAS 5

struct features_1D_t {
    unsigned int w;
    unsigned long mean;
    unsigned long int std_dev;    
};

struct features_2D_t {
    unsigned long magnitude;
    long int radius;
    long int aprx_cov;
    long int corr_coeff;
};

// 20 features per packet (3 removed due to repetitions with the channel ones)
struct packet_features_t {
    // MI
    struct features_1D_t MI;
    // jitter channel
    struct features_1D_t jitter;
    // socket
    struct features_1D_t socket_1D;
    struct features_2D_t socket_2D;
    // channel
    struct features_1D_t channel_1D;
    struct features_2D_t channel_2D;
};

struct all_packet_features_t {
    // struct of struct
    struct packet_features_t packet_features[LAMBDAS];
};

struct ip_addr {
    union {
        unsigned int v4;            // 32-bit IPv4 address
        char v6[IP_ADDR_LEN_V6];    // 128-bit IPv6 address
    };
};

struct packet_infos_t {
    char src_mac[6];
    char dst_mac[6];
    unsigned short eth_proto;
    struct ip_addr src_ip;
    struct ip_addr dst_ip;
    unsigned short ip_proto;
    int sport;
    int dport;
    unsigned short IPType; // 0 -> IPv4, 1 -> IPv6
    unsigned short pkt_len;
    unsigned long long timestamp; // in nanoseconds
};

struct packet_infos_and_features_t {
    struct packet_infos_t my_packet;
    struct all_packet_features_t my_features;
};

static struct packet_infos_and_features_t my_info_feature;

// Callback function to handle the upcoming event
static int handle_event(void *ctx, void *data, size_t data_sz) {
    
    struct packet_infos_and_features_t *e = (struct packet_infos_and_features_t *)data;
    
    my_info_feature.my_packet = e->my_packet;
    my_info_feature.my_features = e->my_features;

    //printf("Src_mac: %s\n", my_info_feature.my_packet.src_mac);
    //printf("First feature: %d, Name: %s\n", e->my_features.packet_features[0].MI.w, "MI - w");
    return 0;
}

int main() {

    // mad id to be inserted every time the eBPF program is rerun
    int map_id = 44; // sudo bpftool map show | grep ringbuf
    int map_fd = -1;
    struct ring_buffer *rb;

    //map_fd = bpf_object__find_map_fd_by_name(obj, "packet_and_features_ring");
    map_fd = bpf_map_get_fd_by_id(map_id);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find map: %s\n", strerror(-map_fd));
        return 1;
    }

    // Create a ring buffer consumer
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for events...\n");

    // Poll the ring buffer for new events
    while (1) {
        int err = ring_buffer__poll(rb, -1); // it is always listening!
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    // Clean the ring buffer
    ring_buffer__free(rb);
    return 0;
}
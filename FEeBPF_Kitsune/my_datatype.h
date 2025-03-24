#ifndef MY_DATATYPE_H
#define MY_DATATYPE_H

#define LAMBDAS 5


/************\
|  POINTERS  |
\************/

struct __attribute__((packed)) arphdr {
    unsigned short int ar_hrd;                /* Format of hardware address.  */
    unsigned short int ar_pro;                /* Format of protocol address.  */
    unsigned char ar_hln;                /* Length of hardware address.  */
    unsigned char ar_pln;                /* Length of protocol address.  */
    unsigned short int ar_op;                /* ARP opcode (command).  */
    unsigned char __ar_sha[6];        /* Sender hardware address.  */
    unsigned int __ar_sip;                /* Sender IP address.  */
    unsigned char __ar_tha[6];        /* Target hardware address.  */
    unsigned int __ar_tip;                /* Target IP address.  */
};

struct pointers_t {
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    //struct ipv6hdr *ip6h;
    //struct tcphdr *tcph;
    //struct udphdr *udph;
    //struct icmp6hdr *icmp6;
    //struct arphdr *arph;
};


/**************************\
|  DECAY FACTOR VARIABLES  |
\**************************/

struct decay_factor_t {
    unsigned long long int gamma;
    unsigned int delta_time;
    unsigned long int exp;
    unsigned int my_shift;
    unsigned short scale;
};


/**********************\
|  RESIDUAL VARIABLES  |
\**********************/

struct all_residual_t {
    int ri[LAMBDAS];
    int rj[LAMBDAS];
    int ri_port[LAMBDAS];
    int rj_port[LAMBDAS];
};


/*********************************\
|  DUMPED INFERENTIAL STATISTICS  |
\*********************************/

// Dumped Inferential Statistics for calculating FEATURES
struct dumped_IS_t{

    unsigned int w;             // pkt counter
    unsigned long LS;           // Linear Sum
    unsigned long long SS;      // Squared Sum
    unsigned long t_last;       // timestamp in nanoseconds
}; //__attribute__((packed));

struct all_dumped_IS_t {

    struct dumped_IS_t dumped_IS[LAMBDAS];
}; //__attribute__((packed));


/*********************\
| FEATURES DEFINITION |
\*********************/

// FEATURES
// ( There are three important attributes: pkt counter, pkt length and timestamp.
//   These features are computated for the pkt length and the delta t of packets. )
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


/*******************\
|   PACKET INFOS    |
\*******************/

#define IP_ADDR_LEN_V4 4   //  4 bytes for IPv4
#define IP_ADDR_LEN_V6 16  // 16 bytes for IPv6

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


/*******************\
|  KEYS DEFINITION  |
\*******************/

struct key_channel_jitter_t {
    struct ip_addr src_ip;
};

struct key_channel_t {
    struct ip_addr src_ip;
    struct ip_addr dst_ip;
};

struct key_MI_t {
    char src_mac[6];
    struct ip_addr src_ip;
};

struct key_socket_t {
    struct ip_addr src_ip;
    unsigned short sport;
    struct ip_addr dst_ip;
    unsigned short dport;
};

struct all_key_t {
    struct key_channel_jitter_t k_c_j;
    struct key_channel_t k_c;
    struct key_MI_t k_mi;
    struct key_socket_t k_s;
};


/*******************\
|  SUPPORT STRUCT   |
\*******************/

struct all_key_support_t {
    struct key_channel_t k_support_ip_i;
    struct key_channel_t k_support_ip_j;
    struct key_socket_t k_support_ip_port_i;
    struct key_socket_t k_support_ip_port_j;
};

struct support_dumped_IS_t {
    long int SR;                 // sum of residuals
    unsigned long long t_last;   // in nanoseconds
};

struct all_support_dumped_IS_t {
    struct support_dumped_IS_t support_dumped_IS[LAMBDAS];
};


struct mean_and_std_dev_t {
    unsigned long mean_i;
    unsigned long mean_j;
    unsigned long std_dev_i;
    unsigned long std_dev_j;
};

/******************\
|  LAMBDA STRUCT   |
\******************/

struct lambda_t {
    int my_lambda[LAMBDAS];
};

struct performance_t {
    unsigned int counter;
    unsigned long bytes;
};


struct packet_infos_and_features_t {
    struct packet_infos_t my_packet;
    struct all_packet_features_t my_features;
};

#endif // MY_DATATYPE_H
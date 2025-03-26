//#include <bcc/proto.h>      // for BCC framework
//#include </usr/lib/x86_64-linux-gnu/perl/5.34.0/CORE/proto.h>
//#include </usr/src/linux-headers-5.15.0-116/arch/x86/include/asm/proto.h>
#include </usr/src/linux-hwe-6.8-headers-6.8.0-52/arch/x86/include/asm/proto.h>
//#include </usr/include/bpf/bpf.h>
#include </usr/src/linux-hwe-6.8-headers-6.8.0-52/include/uapi/linux/bpf.h>
//#include <uapi/linux/bpf.h> // to handle bpf calls from userspace
#include <linux/if_ether.h> // to handle the ethernet layer
#include <linux/ip.h>       // to handle the ipv4 layer
#include <linux/in.h>       // For IP protocols
//#include <linux/if_arp.h>   // for ARP protocol
#include </usr/include/linux/tcp.h>
#include </usr/include/linux/udp.h>
//#include <linux/ipv6.h>     // to handle the ipv6 layer
//#include <linux/icmpv6.h>
//#include <linux/limits.h>
//#include <linux/pkt_cls.h>  // to handle the Traffic Control hooking
#include </usr/src/linux-hwe-6.8-headers-6.8.0-52/include/uapi/linux/limits.h>
//#include <uapi/linux/limits.h>

#include "my_datatype.h"   // my library
//#include </usr/include/bpf/bpf_helpers.h>

//IPv4 -> 4 bytes
//IPv6 -> 16 bytes
//MAC -> 6 bytes
//2^20 = 1048576
//2^19 = 524288
//2^18 = 262144
//2^17 = 131072

/*********************\
|   DATA STRUCTURES   |
\*********************/

// 4 HASH TABLE: one per each stream catalogation (Host Table) -> statistics for 1D features
BPF_HASH(channel_jitter_map, struct key_channel_jitter_t, struct all_dumped_IS_t, 131072); // srcIP + dstIP (Channel jitter)
BPF_HASH(MI_map, struct key_MI_t, struct all_dumped_IS_t, 131072); // srcMAC + srcIP (MI)
BPF_HASH(channel_map, struct key_channel_t, struct all_dumped_IS_t, 131072); // srcIP + dstIP (Channel)
BPF_HASH(socket_map, struct key_socket_t, struct all_dumped_IS_t, 131072); // srcIP + sport + dstIP + dport (Socket)

// 2 SUPPORT HASH TABLE: to collect the RS of the streams -> statistics for 2D features
BPF_HASH(IP_map, struct key_channel_t, struct all_support_dumped_IS_t, 131072); // srcIP + dstIP (Channel)
BPF_HASH(IPport_map, struct key_socket_t, struct all_support_dumped_IS_t, 131072); // srcIP + sport + dstIP + dport (Socket)

// To contain the parsed information, without the usage of the stack
BPF_ARRAY(pointers_map, struct pointers_t, 1);
BPF_ARRAY(keys_map, struct all_key_t, 1);
BPF_ARRAY(keys_support_map, struct all_key_support_t, 1);
BPF_ARRAY(decay_factor_map, struct decay_factor_t, 1);
BPF_ARRAY(residuals_map, struct all_residual_t, 1);
BPF_ARRAY(support_dis_map, struct support_dumped_IS_t, 1);
BPF_ARRAY(lambda_map, struct lambda_t, 1);
BPF_ARRAY(packet_number_map, struct performance_t, 1);
BPF_ARRAY(all_dsi_map, struct all_dumped_IS_t, 1);
BPF_ARRAY(supp_dsi_map, struct all_support_dumped_IS_t, 1);
BPF_ARRAY(mean_and_std_dev_map, struct mean_and_std_dev_t, 1);
BPF_ARRAY(packet_infos_and_features_map, struct packet_infos_and_features_t, 1);

// A ring buffer to share current packet to userspace
BPF_RINGBUF_OUTPUT(packet_and_features_ring, 1);

/***********************\
|   SUPPORT FUNCTIONS   |
\***********************/

// Newton square root approximation to compute statistics
static unsigned long squareRoot(unsigned long a, unsigned long b, short sign) {

    unsigned long n = 0;

    if (!sign)
        // To avoid a possible underflow 
        n = a < b ? (b - a) : (a - b);
    else
        // To avoid possible overflow
        n = ((a + b) < a || (a + b) < b) ? (ULONG_MAX) : (a + b);

    if (n == 0)
        return 0;
    
    unsigned long guess = n >> 1;
    unsigned long next_guess = 0;

    // 25 is a good approximation with the range with are taking into account
    for (int i = 0; i < 25 && guess != 0; i++) {

        next_guess = (guess + n / guess) >> 1;

        if (next_guess >= guess)
            break;

        guess = next_guess; 
    }

    return guess;
}

// Support function to insert a tuple related to 1D statistics when it is not present
static void insert_tuple(struct all_dumped_IS_t my_all_dsi, __u8 map, struct packet_infos_t my_packet, struct all_key_t *my_keys) {

    //JITTER
    if (map == 0) {

        for (int i = 0; i < LAMBDAS; i++){

            my_all_dsi.dumped_IS[i].w = 1;
            my_all_dsi.dumped_IS[i].LS = 0;
            my_all_dsi.dumped_IS[i].SS = 0;
            my_all_dsi.dumped_IS[i].t_last = my_packet.timestamp;

        }

        channel_jitter_map.insert(&(my_keys->k_c_j), &my_all_dsi);
    }
    else {

        for (int i = 0; i < LAMBDAS; i++){

            my_all_dsi.dumped_IS[i].w = 1;
            my_all_dsi.dumped_IS[i].LS = my_packet.pkt_len;
            my_all_dsi.dumped_IS[i].SS = my_packet.pkt_len * my_packet.pkt_len;
            my_all_dsi.dumped_IS[i].t_last = my_packet.timestamp;

        }

        // MAC-IP
        if (map == 1)
            MI_map.insert(&(my_keys->k_mi), &my_all_dsi);
        // CHANNEL
        else if (map == 2)
            channel_map.insert(&(my_keys->k_c), &my_all_dsi);
        // SOCKET
        else
            socket_map.insert(&(my_keys->k_s), &my_all_dsi);
    }

}

// Support function to update a tuple related to 1D statistics
static void update_tuple(struct all_dumped_IS_t * pointer, __u8 map, struct packet_infos_t my_packet, struct decay_factor_t *decay_factor, struct lambda_t *my_lambda_p) {

    // JITTER
    if (map == 0) {

        for (int i = 0; i < LAMBDAS; i++){

            decay_factor->delta_time = my_packet.timestamp - pointer->dumped_IS[i].t_last;

            decay_factor->my_shift = my_lambda_p->my_lambda[i] * decay_factor->delta_time / decay_factor->scale;
            //exp = (lambda[i]*delta_time)/128;
            // delta_time in --> ns <--
            // 2**-(something) = (1/2)**(something)

            pointer->dumped_IS[i].w = (pointer->dumped_IS[i].w >> decay_factor->my_shift) + 1;
            pointer->dumped_IS[i].LS = (pointer->dumped_IS[i].LS >> decay_factor->my_shift) + decay_factor->delta_time;
            if (decay_factor->delta_time > 4294967295UL) // Check if delta_time is too large to square safely
                pointer->dumped_IS[i].SS = ULONG_MAX;
            else
                pointer->dumped_IS[i].SS = (pointer->dumped_IS[i].SS >> decay_factor->my_shift) + decay_factor->delta_time * decay_factor->delta_time;
            pointer->dumped_IS[i].t_last = my_packet.timestamp;

        }

    }
    else {

        // ALL THE OTHER MAPS
        for (int i = 0; i < LAMBDAS; i++){

            decay_factor->delta_time = my_packet.timestamp - pointer->dumped_IS[i].t_last;

            decay_factor->my_shift = my_lambda_p->my_lambda[i] * decay_factor->delta_time / decay_factor->scale;
            //exp = (lambda[i]*delta_time)/128; // delta_time in --> ns <--
            // 2**-(something) = (1/2)**(something) => bit shifting

            pointer->dumped_IS[i].w = (pointer->dumped_IS[i].w >> decay_factor->my_shift) + 1;
            pointer->dumped_IS[i].LS = (pointer->dumped_IS[i].LS >> decay_factor->my_shift) + my_packet.pkt_len;
            pointer->dumped_IS[i].SS = (pointer->dumped_IS[i].SS >> decay_factor->my_shift) + my_packet.pkt_len * my_packet.pkt_len;          
            pointer->dumped_IS[i].t_last = my_packet.timestamp;

        }
    }

}


int xdp_ingress(struct xdp_md *ctx){

    /*******************\
    |   PARSING PHASE   |
    \*******************/

    // The index key for not-overloading-stack arrays
    int key = 0;

    // To store all the pointers which are required to allocate
    struct pointers_t *my_pointers = pointers_map.lookup(&key);

    if (my_pointers == NULL) {
        return XDP_DROP;
    }

    // Creating the structure for the ring buffer
    // To store the packet info and the features related to it
    struct packet_infos_and_features_t *my_final_package = packet_infos_and_features_map.lookup(&key);

    if (my_final_package == NULL)
        return XDP_DROP;

    // To store the timestamp
    my_final_package->my_packet.timestamp = bpf_ktime_get_ns();

    // To point at the beginning and the end of the packet
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet layer
    my_pointers->eth = data;

    // Check if the ethernet layer is misformatted
    // it's like (my_pointers->eth + sizeof(struct ethhdr))
    // (void *) to avoid annoying warning with the compiler due to
    // data_end has to be void * because at the beginning
    // it's not possible to anticipate the exact size of the pkt
    // and as consequence, the pkt type
    if ((void *)(my_pointers->eth + 1) > data_end)
        return XDP_DROP;

    // Pointer used to reduce the pointers on the stack
    // because the calls like "my_pointers->eth->h_source" are not working well
    void * multipurpose_pointer = my_pointers->eth;
    my_final_package->my_packet.eth_proto = bpf_htons(((struct ethhdr *) multipurpose_pointer)->h_proto);

    // Storing MACs
    __builtin_memcpy(my_final_package->my_packet.src_mac, ((struct ethhdr *) multipurpose_pointer)->h_source, 6);
    __builtin_memcpy(my_final_package->my_packet.dst_mac, ((struct ethhdr *) multipurpose_pointer)->h_dest, 6);

    if (my_final_package->my_packet.eth_proto == ETH_P_IP){ // case: IPv4
        
        my_pointers->iph = data + sizeof(struct ethhdr);

        if ((void *)(my_pointers->iph + 1) > data_end)
            return XDP_DROP;

        multipurpose_pointer = my_pointers->iph;
        my_final_package->my_packet.src_ip.v4 = ((struct iphdr *) multipurpose_pointer)->saddr;
        my_final_package->my_packet.dst_ip.v4 = ((struct iphdr *) multipurpose_pointer)->daddr;
        my_final_package->my_packet.IPType = 0;
        my_final_package->my_packet.pkt_len = bpf_ntohs(((struct iphdr *) multipurpose_pointer)->tot_len);
        my_final_package->my_packet.ip_proto = ((struct iphdr *) multipurpose_pointer)->protocol;

        if (my_final_package->my_packet.dst_ip.v4 == 0)
            return XDP_PASS;

        if (my_final_package->my_packet.ip_proto == IPPROTO_ICMP) { // case: ICMP

            my_final_package->my_packet.sport = -1;
            my_final_package->my_packet.dport = -1;

        } else if (my_final_package->my_packet.ip_proto == IPPROTO_TCP) { // Packet is TCP
            
            //my_pointers->tcph = (struct tcphdr *) (my_pointers->iph);
            //multipurpose_pointer = my_pointers->tcph;
            my_final_package->my_packet.sport = bpf_ntohs(((struct tcphdr *) multipurpose_pointer)->source);
            my_final_package->my_packet.dport = bpf_ntohs(((struct tcphdr *) multipurpose_pointer)->dest);
            
        } else if (my_final_package->my_packet.ip_proto == IPPROTO_UDP) { // Packet is UDP
            
            //my_pointers->udph = (struct udphdr *)(my_pointers->iph);
            //multipurpose_pointer = my_pointers->udph;
            my_final_package->my_packet.sport = bpf_ntohs(((struct udphdr *) multipurpose_pointer)->source);
            my_final_package->my_packet.dport = bpf_ntohs(((struct udphdr *) multipurpose_pointer)->dest);

        } else {
            bpf_trace_printk("IPv4 packet with unhandled protocol: %d\n", my_final_package->my_packet.ip_proto);
            return XDP_PASS;
        }

    } else if (my_final_package->my_packet.eth_proto == ETH_P_IPV6) {  // case: IPv6
        /* this should be restructured...
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + sizeof(struct ethhdr));

        if ((void *)(ip6h + 1) > data_end) {
            return XDP_PASS;
        }
        
        __builtin_memcpy(my_packet.src_ip.v6, ip6h->daddr.in6_u, 16);
        __builtin_memcpy(my_packet.dst_ip.v6, ip6h->daddr.in6_u, 16);
        my_packet.IPType = 1;
        my_packet.pkt_len = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + bpf_ntohs(ip6h->payload_len);

        // Checking the next header field to identify the transport layer protocol
        my_packet.ip_proto = ip6h->nexthdr;

        if (my_packet->ip_proto == IPPROTO_TCP) {

            struct tcphdr *tcph = (struct tcphdr *)(ip6h + sizeof(struct ipv6hdr));

            if ((void *)(tcph + 1) > data_end) {
                return XDP_PASS;
            }

            my_packet.sport = bpf_ntohs(tcph->source);
            my_packet.dport = bpf_ntohs(tcph->dest);

        } else if (my_packet->ip_proto == IPPROTO_UDP) {

            struct udphdr *udph = (struct udphdr *)(ip6h + sizeof(struct ipv6hdr));

            if ((void *)(udph + 1) > data_end) {
                return XDP_PASS;
            }

            my_packet.sport = bpf_ntohs(udph->source);
            my_packet.dport = bpf_ntohs(udph->dest);

        } else if (my_packet.ip_proto == IPPROTO_ICMPV6) {

            struct icmp6hdr *icmp6 = (struct icmp6hdr *)(ip6h + sizeof(struct ipv6hdr));

            if ((void *)(icmp6 + 1) > data_end) {
                return XDP_PASS;
            }

            my_packet.sport = -1;
            my_packet.dport = -1;
           
        } else {
            bpf_trace_printk("IPv6 packet with unhandled protocol: %d\n", my_packet.ip_proto);
        }

        */
        bpf_trace_printk("Packet with unhandled protocol (IPv6): %d\n", my_final_package->my_packet.eth_proto);
        return XDP_DROP;     // we don't care about it

    } else if (my_final_package->my_packet.eth_proto == ETH_P_ARP) {  // case: ARP
        
        struct arphdr *arph = (struct arphdr *) (data + sizeof(struct ethhdr));
    
        if ((void *)(arph + 1) > data_end)
            return XDP_DROP;

        my_final_package->my_packet.IPType = 0;
        my_final_package->my_packet.sport = -2;
        my_final_package->my_packet.dport = -2;
        my_final_package->my_packet.src_ip.v4 = arph->__ar_sip;
        my_final_package->my_packet.dst_ip.v4 = arph->__ar_tip;
        my_final_package->my_packet.pkt_len = sizeof(struct ethhdr) + sizeof(struct arphdr); // + 20;
        
    } else {
        bpf_trace_printk("Packet with unhandled protocol: %d\n", my_final_package->my_packet.eth_proto);
        return XDP_DROP;     // we don't care about it
    }

    /*
    bpf_trace_printk("PACKET RECEIVED! at time %ld", my_packet->timestamp);
    bpf_trace_printk("srcMac %x | dstMac %x | eth proto %x", my_packet->src_mac, my_packet->dst_mac, bpf_htons(my_packet->eth_proto)),
    bpf_trace_printk("srcIP %x | dstIP %d", my_packet->src_ip.v4, my_packet->dst_ip.v4);
    bpf_trace_printk("protocol %x | tot_len %d", my_packet->ip_proto, my_packet->pkt_len);
    bpf_trace_printk("sport: %d | dport: %d | IPType: %d", my_packet->sport, my_packet->dport, my_packet->IPType);
    bpf_trace_printk("----------------");
    bpf_trace_printk("Source MAC: %02x:%02x:%02x:", my_packet->src_mac[0], my_packet->src_mac[1], my_packet->src_mac[2]);
    bpf_trace_printk("Source MAC: %02x:%02x:%02x\n", my_packet->src_mac[3], my_packet->src_mac[4], my_packet->src_mac[5]);
    */



    /****************\
    |   KEYS PHASE   |
    \****************/

    // SETTING THE KEYS FOR ALL MAPS
    struct all_key_t *my_keys = keys_map.lookup(&key);

    if (my_keys == NULL) {
        return XDP_DROP;
    }

    // Channel jitter key \\

    if (my_final_package->my_packet.IPType == 0) {
        my_keys->k_c_j.src_ip.v4 = my_final_package->my_packet.src_ip.v4;
    } else {
        __builtin_memcpy(my_keys->k_c_j.src_ip.v6, my_final_package->my_packet.src_ip.v6, 16);
    }

    // Channel key \\

    if (my_final_package->my_packet.IPType == 0) {
        my_keys->k_c.src_ip.v4 = my_final_package->my_packet.src_ip.v4;
        my_keys->k_c.dst_ip.v4 = my_final_package->my_packet.dst_ip.v4;
    } else {
        __builtin_memcpy(my_keys->k_c.src_ip.v6, my_final_package->my_packet.src_ip.v6, 16);
        __builtin_memcpy(my_keys->k_c.dst_ip.v6, my_final_package->my_packet.dst_ip.v6, 16);
    }

    // MAC-IP key \\

    __builtin_memcpy(my_keys->k_mi.src_mac, my_final_package->my_packet.src_mac, 6);

    if (my_final_package->my_packet.IPType == 0) {
        my_keys->k_mi.src_ip.v4 = my_final_package->my_packet.src_ip.v4;
    } else {
        __builtin_memcpy(my_keys->k_mi.src_ip.v6, my_final_package->my_packet.src_ip.v6, 16);
    }
    
    // Socket key
    // 1 "linux" byte due to there is no support for 1 bit
    __u8 yes_socket = 1;

    if (my_final_package->my_packet.IPType == 0) {
        my_keys->k_s.src_ip.v4 = my_final_package->my_packet.src_ip.v4;
        my_keys->k_s.dst_ip.v4 = my_final_package->my_packet.dst_ip.v4;
    } else {
        __builtin_memcpy(my_keys->k_s.src_ip.v6, my_final_package->my_packet.src_ip.v6, 16);
        __builtin_memcpy(my_keys->k_s.dst_ip.v6, my_final_package->my_packet.dst_ip.v6, 16);
    }

    if ((my_final_package->my_packet.sport >= 1 && my_final_package->my_packet.dport >= 1)
    ) {
        my_keys->k_s.sport = my_final_package->my_packet.sport;
        my_keys->k_s.dport = my_final_package->my_packet.dport;
    } else {
        // NO SOCKET
        yes_socket = 0;
    }


    // Support keys
    struct all_key_support_t *my_support_keys = keys_support_map.lookup(&key);

    if (my_support_keys == NULL) {
        return XDP_DROP;
    }

    // IP map
    if (my_final_package->my_packet.IPType == 0) {
        my_support_keys->k_support_ip_i.src_ip.v4 = my_final_package->my_packet.src_ip.v4;
        my_support_keys->k_support_ip_i.dst_ip.v4 = my_final_package->my_packet.dst_ip.v4;
        my_support_keys->k_support_ip_j.src_ip.v4 = my_final_package->my_packet.dst_ip.v4;
        my_support_keys->k_support_ip_j.dst_ip.v4 = my_final_package->my_packet.src_ip.v4;
    } else {
        __builtin_memcpy(my_support_keys->k_support_ip_i.src_ip.v6, my_final_package->my_packet.src_ip.v6, 16);
        __builtin_memcpy(my_support_keys->k_support_ip_i.dst_ip.v6, my_final_package->my_packet.dst_ip.v6, 16);
        __builtin_memcpy(my_support_keys->k_support_ip_j.src_ip.v6, my_final_package->my_packet.dst_ip.v6, 16);
        __builtin_memcpy(my_support_keys->k_support_ip_j.dst_ip.v6, my_final_package->my_packet.src_ip.v6, 16);
    }

    // IP port map
    if (yes_socket) {

        if (my_final_package->my_packet.IPType == 0) {
            my_support_keys->k_support_ip_port_i.src_ip.v4 = my_final_package->my_packet.src_ip.v4;
            my_support_keys->k_support_ip_port_i.dst_ip.v4 = my_final_package->my_packet.dst_ip.v4;
            my_support_keys->k_support_ip_port_j.src_ip.v4 = my_final_package->my_packet.dst_ip.v4;
            my_support_keys->k_support_ip_port_j.dst_ip.v4 = my_final_package->my_packet.src_ip.v4;
        } else {
            __builtin_memcpy(my_support_keys->k_support_ip_port_i.src_ip.v6, my_final_package->my_packet.src_ip.v6, 16);
            __builtin_memcpy(my_support_keys->k_support_ip_port_i.dst_ip.v6, my_final_package->my_packet.dst_ip.v6, 16);
            __builtin_memcpy(my_support_keys->k_support_ip_port_j.src_ip.v6, my_final_package->my_packet.dst_ip.v6, 16);
            __builtin_memcpy(my_support_keys->k_support_ip_port_j.dst_ip.v6, my_final_package->my_packet.src_ip.v6, 16);
        }

        my_support_keys->k_support_ip_port_i.sport = my_final_package->my_packet.sport;
        my_support_keys->k_support_ip_port_i.dport = my_final_package->my_packet.dport;
        my_support_keys->k_support_ip_port_j.sport = my_final_package->my_packet.dport;
        my_support_keys->k_support_ip_port_j.dport = my_final_package->my_packet.sport;

    }
    


    /*****************************************\
    |   DUMPED INCREMENTAL STATISTICS PHASE   |
    \*****************************************/

    // To store lambda parameters
    struct lambda_t *my_lambda_p = lambda_map.lookup(&key);
    
    if (my_lambda_p == NULL)
        return XDP_DROP;

    // Everything is multiplied by 128 due to the not presence of floating point
    //  5    3   1   0.1   0.01
    //  640  384 128 13    1
    my_lambda_p->my_lambda[0] = 1;
    my_lambda_p->my_lambda[1] = 13;
    my_lambda_p->my_lambda[2] = 128;
    my_lambda_p->my_lambda[3] = 384;
    my_lambda_p->my_lambda[4] = 640;

    // To store all the variables linked to the decay factor
    struct decay_factor_t* decay_factor = decay_factor_map.lookup(&key);

    if (decay_factor == NULL)
        return XDP_DROP;

    decay_factor->gamma = 1;
    decay_factor->delta_time = 0;
    decay_factor->exp = 0;
    decay_factor->scale = 128;

    // To store packet counter and the amount of bytes collected
    struct performance_t *packet_number = packet_number_map.lookup(&key);

    if (packet_number == NULL)
        return XDP_DROP;
    
    // First packet
    if (packet_number->counter == 0) {

        packet_number->counter = 1;
        packet_number->bytes = my_final_package->my_packet.pkt_len;
    }
    else {

        packet_number->counter++;
        packet_number->bytes += my_final_package->my_packet.pkt_len;
    }
    

    struct all_dumped_IS_t my_all_dsi = {0};


      // -------------------------------------------------------------------- \\
     // ------------------------- CHANNEL JITTER MAP ------------------------- \\
    // ------------------------------------------------------------------------ \\

    struct all_dumped_IS_t *channel_jitter_dsi_fd = channel_jitter_map.lookup(&(my_keys->k_c_j));

    if (channel_jitter_dsi_fd == NULL) {

        insert_tuple(my_all_dsi, 0, my_final_package->my_packet, my_keys);
    }
    else {
        
        update_tuple(channel_jitter_dsi_fd, 0, my_final_package->my_packet, decay_factor, my_lambda_p);
    }

      // -------------------------------------------------------------------- \\
     // ----------------------------- MAC-IP MAP ----------------------------- \\
    // ------------------------------------------------------------------------ \\

    struct all_dumped_IS_t *mi_dsi_fd = MI_map.lookup(&(my_keys->k_mi));

    if (mi_dsi_fd == NULL) {

        insert_tuple(my_all_dsi, 1, my_final_package->my_packet, my_keys);

    }
    else {
        
        update_tuple(mi_dsi_fd, 1, my_final_package->my_packet, decay_factor, my_lambda_p);
    }

      // --------------------------------------------------------------------- \\
     // ----------------------------- CHANNEL MAP ----------------------------- \\
    // ------------------------------------------------------------------------- \\

    struct all_dumped_IS_t *channel_dsi_fd = channel_map.lookup(&(my_keys->k_c));

    if (channel_dsi_fd == NULL) {

        insert_tuple(my_all_dsi, 2, my_final_package->my_packet, my_keys);

    } else {

        update_tuple(channel_dsi_fd, 2, my_final_package->my_packet, decay_factor, my_lambda_p);

    }

      // ------------------------------------------------------------------- \\
     // ----------------------------- SOCKET MAP ---------------------------- \\
    // ----------------------------------------------------------------------- \\

    if (yes_socket) {

        struct all_dumped_IS_t *socket_dsi_fd = socket_map.lookup(&(my_keys->k_s));

        if (socket_dsi_fd == NULL) {

            insert_tuple(my_all_dsi, 3, my_final_package->my_packet, my_keys);
        }
        else {
            
            update_tuple(socket_dsi_fd, 3, my_final_package->my_packet, decay_factor, my_lambda_p);
        }

    }

      // --------------------------------------------------------------------- \\
     // ---------------- RESIDUAL COMPUTATION for CHANNEL MAP ----------------- \\
    // ------------------------------------------------------------------------- \\

    struct all_residual_t *residual = residuals_map.lookup(&key);

    if (residual == NULL)
        return XDP_DROP;

    // Computing the residuals for both directions

    struct all_dumped_IS_t *i_fd = channel_map.lookup(&(my_support_keys->k_support_ip_i));

    if (i_fd != NULL) {

        for (int i = 0; i < LAMBDAS; i++)
            residual->ri[i] = my_final_package->my_packet.pkt_len - (int)(i_fd->dumped_IS[i].LS / i_fd->dumped_IS[i].w);

    } else {
        // useless because this is for i which was updated before
        for (int i = 0; i < LAMBDAS; i++)
            residual->ri[i] = 0;
    }

    struct all_dumped_IS_t *j_fd = channel_map.lookup(&(my_support_keys->k_support_ip_j));

    if (j_fd != NULL) {

        for (int i = 0; i < LAMBDAS; i++)
            residual->rj[i] = my_final_package->my_packet.pkt_len - (int)(j_fd->dumped_IS[i].LS / j_fd->dumped_IS[i].w);

    } else {
        for (int i = 0; i < LAMBDAS; i++)
            residual->rj[i] = 0;
    }

    /*
    bpf_trace_printk("Residuals 0, %ld, %ld", residual->ri[0], residual->rj[0]);
    bpf_trace_printk("Residuals 1, %ld, %ld", residual->ri[1], residual->rj[1]);
    bpf_trace_printk("Residuals 2, %ld, %ld", residual->ri[2], residual->rj[2]);
    bpf_trace_printk("Residuals 3, %ld, %ld", residual->ri[3], residual->rj[3]);
    bpf_trace_printk("Residuals 4, %ld, %ld", residual->ri[4], residual->rj[4]);
    */

    // Storing the SR after checking if a previous initialization was done

    struct all_support_dumped_IS_t *supp_dsi = supp_dsi_map.lookup(&key);

    if (supp_dsi == NULL)
        return XDP_DROP;

    struct all_support_dumped_IS_t *IP_map_fd_i = IP_map.lookup(&(my_support_keys->k_support_ip_i));
    struct all_support_dumped_IS_t *IP_map_fd_j = IP_map.lookup(&(my_support_keys->k_support_ip_j));

    // if there is no initialization for this stream
    if (IP_map_fd_i == NULL) {

        if (IP_map_fd_j == NULL) {
            // if there is no tuple even for the reverse stream in our support table
            // the tuple will be inserted for the 'i' stream
            for (int i = 0; i < LAMBDAS; i++) {

                supp_dsi->support_dumped_IS[i].SR = (residual->ri[i]) * (residual->rj[i]);
                supp_dsi->support_dumped_IS[i].t_last = my_final_package->my_packet.timestamp;

            }

            IP_map.insert(&(my_support_keys->k_support_ip_i), supp_dsi);
        }
        else {
            // it was already initialized but in the opposite way
            // it has to be just updated
            for (int i = 0; i < LAMBDAS; i++) {

                IP_map_fd_j->support_dumped_IS[i].SR = (IP_map_fd_j->support_dumped_IS[i].SR >> decay_factor->my_shift) + (residual->ri[i]) * (residual->rj[i]);
                IP_map_fd_j->support_dumped_IS[i].t_last = my_final_package->my_packet.timestamp;

            }
        }
                

    } else {
        // the stream i has already a tuple
        // and it has to be just updated
        for (int i = 0; i < LAMBDAS; i++) {

            IP_map_fd_i->support_dumped_IS[i].SR = (IP_map_fd_i->support_dumped_IS[i].SR >> decay_factor->my_shift) + (residual->ri[i]) * (residual->rj[i]);
            IP_map_fd_i->support_dumped_IS[i].t_last = my_final_package->my_packet.timestamp;

        }

    }

      // --------------------------------------------------------------------- \\
     // ----------------- RESIDUAL COMPUTATION for SOCKET MAP ----------------- \\
    // ------------------------------------------------------------------------- \\

    if (yes_socket) {

        struct all_dumped_IS_t *i_port_fd = socket_map.lookup(&(my_support_keys->k_support_ip_port_i));

        if (i_port_fd != NULL) {

            for (int i = 0; i < LAMBDAS; i++)
                residual->ri_port[i] = my_final_package->my_packet.pkt_len - (int)(i_port_fd->dumped_IS[i].LS / i_port_fd->dumped_IS[i].w);

        } else {
            // useless because this is for i which was updated before
            for (int i = 0; i < LAMBDAS; i++)
                residual->ri_port[i] = 0;
        }

        struct all_dumped_IS_t *j_port_fd = socket_map.lookup(&(my_support_keys->k_support_ip_port_j));

        if (j_port_fd != NULL) {

            for (int i = 0; i < LAMBDAS; i++)
                residual->rj_port[i] = my_final_package->my_packet.pkt_len - (int)(j_port_fd->dumped_IS[i].LS / j_port_fd->dumped_IS[i].w);

        } else {
            for (int i = 0; i < LAMBDAS; i++)
                residual->rj_port[i] = 0;
        }

        // here the supp_dsi is used again to not overload the memory of stack

        struct all_support_dumped_IS_t *IPport_map_fd_i = IPport_map.lookup(&(my_support_keys->k_support_ip_port_i));
        struct all_support_dumped_IS_t *IPport_map_fd_j = IPport_map.lookup(&(my_support_keys->k_support_ip_port_j));

        // if there is no initialization for this stream
        if (IPport_map_fd_i == NULL) {

            if (IPport_map_fd_j == NULL) {
                // if there is no tuple even for the reverse stream in our support table, the i stream will be set
                for (int i = 0; i < LAMBDAS; i++) {

                    supp_dsi->support_dumped_IS[i].SR = (residual->ri_port[i]) * (residual->rj_port[i]);
                    supp_dsi->support_dumped_IS[i].t_last = my_final_package->my_packet.timestamp;

                }

                IPport_map.insert(&(my_support_keys->k_support_ip_port_i), supp_dsi);
            }
            else {
                // it was already initialized but in the opposite way and it has to be updated
                for (int i = 0; i < LAMBDAS; i++) {

                    IPport_map_fd_j->support_dumped_IS[i].SR = (IPport_map_fd_j->support_dumped_IS[i].SR >> decay_factor->my_shift) + (residual->ri_port[i]) * (residual->rj_port[i]);
                    IPport_map_fd_j->support_dumped_IS[i].t_last = my_final_package->my_packet.timestamp;

                }
            }

        } else {
            // the stream i has already a tuple and it has to be updated
            for (int i = 0; i < LAMBDAS; i++) {

                IPport_map_fd_i->support_dumped_IS[i].SR = (IPport_map_fd_i->support_dumped_IS[i].SR >> decay_factor->my_shift) + (residual->ri_port[i]) * (residual->rj_port[i]);
                IPport_map_fd_i->support_dumped_IS[i].t_last = my_final_package->my_packet.timestamp;

            }

        }
    }



    /*********************\
    |    FEATURE PHASE    |
    \*********************/

    // To avoid to calculate mean and std_dev everytime
    struct mean_and_std_dev_t * my_mean_and_std_dev = mean_and_std_dev_map.lookup(&key);

    if (my_mean_and_std_dev == NULL)
        return XDP_DROP;

    my_mean_and_std_dev->mean_j = 0;
    my_mean_and_std_dev->mean_i = 0;
    my_mean_and_std_dev->std_dev_i = 0;
    my_mean_and_std_dev->std_dev_j = 0;

    if (packet_number == NULL)
        return XDP_DROP;

    if (my_final_package == NULL)
        return XDP_DROP;

      // --------------------------------------------------------------------- \\
     // ----------------- FEATURES COMPUTATION for MAC-IP MAP ----------------- \\
    // ------------------------------------------------------------------------- \\

    if (mi_dsi_fd == NULL)
        return XDP_DROP;

    for (int i = 0; i < LAMBDAS; i++) {

        my_final_package->my_features.packet_features[i].MI.w = mi_dsi_fd->dumped_IS[i].w;
        my_final_package->my_features.packet_features[i].MI.mean = mi_dsi_fd->dumped_IS[i].LS / mi_dsi_fd->dumped_IS[i].w;
        my_final_package->my_features.packet_features[i].MI.std_dev = squareRoot(
                mi_dsi_fd->dumped_IS[i].SS / mi_dsi_fd->dumped_IS[i].w,
                my_final_package->my_features.packet_features[i].MI.mean * my_final_package->my_features.packet_features[i].MI.mean,
                0
            );
    }

      // --------------------------------------------------------------------- \\
     // ------------- FEATURES COMPUTATION for CHANNEL JITTER MAP ------------- \\
    // ------------------------------------------------------------------------- \\

    if (channel_jitter_dsi_fd == NULL)
        return XDP_DROP;
    
    for (int i = 0; i < LAMBDAS; i++) {
        my_final_package->my_features.packet_features[i].jitter.w = channel_jitter_dsi_fd->dumped_IS[i].w;
        my_final_package->my_features.packet_features[i].jitter.mean = channel_jitter_dsi_fd->dumped_IS[i].LS / channel_jitter_dsi_fd->dumped_IS[i].w;
        my_final_package->my_features.packet_features[i].jitter.std_dev = squareRoot(
                channel_jitter_dsi_fd->dumped_IS[i].SS / channel_jitter_dsi_fd->dumped_IS[i].w,
                my_final_package->my_features.packet_features[i].jitter.mean * my_final_package->my_features.packet_features[i].jitter.mean,
                0
            );
    }

      // --------------------------------------------------------------------- \\
     // ----------------- FEATURES COMPUTATION for SOCKET MAP ----------------- \\
    // ------------------------------------------------------------------------- \\

    if (yes_socket) {

        struct all_dumped_IS_t *socket_stream_j = socket_map.lookup(&(my_support_keys->k_support_ip_port_j));
        struct all_dumped_IS_t *socket_dsi_fd = socket_map.lookup(&(my_keys->k_s));
        __u8 no_stream_j = 0;

        struct all_support_dumped_IS_t *IPport_map_fd_i = IPport_map.lookup(&(my_support_keys->k_support_ip_port_i));
        struct all_support_dumped_IS_t *IPport_map_fd_j = IPport_map.lookup(&(my_support_keys->k_support_ip_port_j));

        if (socket_stream_j == NULL)
            no_stream_j = 1;

        if (socket_dsi_fd == NULL)
            return XDP_DROP;

        for (int i = 0; i < LAMBDAS; i++) {

            if (no_stream_j)
                my_mean_and_std_dev->mean_j = 0;
            else
                my_mean_and_std_dev->mean_j = socket_stream_j->dumped_IS[i].LS / socket_stream_j->dumped_IS[i].w;
        
            my_mean_and_std_dev->mean_i = socket_dsi_fd->dumped_IS[i].LS / socket_dsi_fd->dumped_IS[i].w;

            my_mean_and_std_dev->std_dev_i = squareRoot(socket_dsi_fd->dumped_IS[i].SS / socket_dsi_fd->dumped_IS[i].w, my_mean_and_std_dev->mean_i * my_mean_and_std_dev->mean_i, 0);
            
            if (no_stream_j)
                my_mean_and_std_dev->std_dev_j = 0;
            else
                my_mean_and_std_dev->std_dev_j = squareRoot(socket_stream_j->dumped_IS[i].SS / socket_stream_j->dumped_IS[i].w, my_mean_and_std_dev->mean_j * my_mean_and_std_dev->mean_j, 0);
            
            //1D

            // Weight
            my_final_package->my_features.packet_features[i].socket_1D.w = socket_dsi_fd->dumped_IS[i].w;
            // Mean = LS/w
            my_final_package->my_features.packet_features[i].socket_1D.mean = my_mean_and_std_dev->mean_i;
            // Standard Deviation = sqrt( abs(SS/w - (LS/w)^2) )
            my_final_package->my_features.packet_features[i].socket_1D.std_dev = my_mean_and_std_dev->std_dev_i;
            
            //2D
            
            // Magnitude = sqrt( mean_i^2 + mean_j^2 )
            my_final_package->my_features.packet_features[i].socket_2D.magnitude = squareRoot(my_mean_and_std_dev->mean_i * my_mean_and_std_dev->mean_i, my_mean_and_std_dev->mean_j * my_mean_and_std_dev->mean_j, 1);
            
            // Radius = sqrt( var_i^2 + var_j^2 )
            my_final_package->my_features.packet_features[i].socket_2D.radius = squareRoot(my_mean_and_std_dev->std_dev_i * my_mean_and_std_dev->std_dev_i, my_mean_and_std_dev->std_dev_j * my_mean_and_std_dev->std_dev_j, 1);
            
            // Approximated Covariance = SRij / (wi + wj)
            if (IPport_map_fd_i != NULL) {

                if (IPport_map_fd_i->support_dumped_IS[i].SR >= 0) {

                    if (no_stream_j)
                        my_final_package->my_features.packet_features[i].socket_2D.aprx_cov = ((unsigned long) IPport_map_fd_i->support_dumped_IS[i].SR) / socket_dsi_fd->dumped_IS[i].w;
                    else
                        my_final_package->my_features.packet_features[i].socket_2D.aprx_cov = ((unsigned long) IPport_map_fd_i->support_dumped_IS[i].SR) / (socket_dsi_fd->dumped_IS[i].w + socket_stream_j->dumped_IS[i].w);
                }
                else {
                    if (no_stream_j)
                        my_final_package->my_features.packet_features[i].socket_2D.aprx_cov = ((unsigned long)(-1 * IPport_map_fd_i->support_dumped_IS[i].SR)) / socket_dsi_fd->dumped_IS[i].w;
                    else
                        my_final_package->my_features.packet_features[i].socket_2D.aprx_cov = ((unsigned long)(-1 * IPport_map_fd_i->support_dumped_IS[i].SR)) / (socket_dsi_fd->dumped_IS[i].w + socket_stream_j->dumped_IS[i].w);
                    
                    my_final_package->my_features.packet_features[i].socket_2D.aprx_cov = -1 * ((long int) my_final_package->my_features.packet_features[i].socket_2D.aprx_cov);
                }
            }
            else if (IPport_map_fd_j != NULL) {

                if (IPport_map_fd_j->support_dumped_IS[i].SR >= 0) {

                    if (no_stream_j)
                        my_final_package->my_features.packet_features[i].socket_2D.aprx_cov = ((unsigned long) IPport_map_fd_j->support_dumped_IS[i].SR) / socket_dsi_fd->dumped_IS[i].w;
                    else
                        my_final_package->my_features.packet_features[i].socket_2D.aprx_cov = ((unsigned long) IPport_map_fd_j->support_dumped_IS[i].SR) / (socket_dsi_fd->dumped_IS[i].w + socket_stream_j->dumped_IS[i].w);
                }
                else {
                    if (no_stream_j)
                        my_final_package->my_features.packet_features[i].socket_2D.aprx_cov = ((unsigned long)(-1 * IPport_map_fd_j->support_dumped_IS[i].SR)) / socket_dsi_fd->dumped_IS[i].w;
                    else
                        my_final_package->my_features.packet_features[i].socket_2D.aprx_cov = ((unsigned long)(-1 * IPport_map_fd_j->support_dumped_IS[i].SR)) / (socket_dsi_fd->dumped_IS[i].w + socket_stream_j->dumped_IS[i].w);
                    
                    my_final_package->my_features.packet_features[i].socket_2D.aprx_cov = -1 * ((long int) my_final_package->my_features.packet_features[i].socket_2D.aprx_cov);
                }
                
            }

            // Correlation Coefficient = Approx.Cov / (std_dev_i * std_dev_j)
            if (my_mean_and_std_dev->std_dev_j == 0 || my_mean_and_std_dev->std_dev_i == 0)
                my_final_package->my_features.packet_features[i].socket_2D.corr_coeff = 0;
            else {
                my_final_package->my_features.packet_features[i].socket_2D.corr_coeff = (my_final_package->my_features.packet_features[i].socket_2D.aprx_cov * 100000) / (my_mean_and_std_dev->std_dev_i * my_mean_and_std_dev->std_dev_j);
                
                if (my_final_package->my_features.packet_features[i].socket_2D.corr_coeff > 100000)
                    my_final_package->my_features.packet_features[i].socket_2D.corr_coeff = 100000;

                else if (my_final_package->my_features.packet_features[i].socket_2D.corr_coeff < -100000)
                    my_final_package->my_features.packet_features[i].socket_2D.corr_coeff = -100000;
                
            }
        }

    }
    else  {

        // if no socket (no ports), everything is ZERO
        for (int i = 0; i < LAMBDAS; i++) {

            my_final_package->my_features.packet_features[i].socket_1D.w = 0;
            my_final_package->my_features.packet_features[i].socket_1D.mean = 0;
            my_final_package->my_features.packet_features[i].socket_1D.std_dev = 0;
            my_final_package->my_features.packet_features[i].socket_2D.magnitude = 0;
            my_final_package->my_features.packet_features[i].socket_2D.radius = 0;
            my_final_package->my_features.packet_features[i].socket_2D.aprx_cov = 0;
            my_final_package->my_features.packet_features[i].socket_2D.corr_coeff = 0;
        }
    }

      // --------------------------------------------------------------------- \\
     // ---------------- FEATURES COMPUTATION for CHANNEL MAP ----------------- \\
    // ------------------------------------------------------------------------- \\

    struct all_dumped_IS_t *channel_stream_j = channel_map.lookup(&(my_support_keys->k_support_ip_j));
    __u8 no_stream_j = 0;

    if (channel_stream_j == NULL)
        no_stream_j = 1;

    if (channel_dsi_fd == NULL)
        return XDP_DROP;
    
    for (int i = 0; i < LAMBDAS; i++) {

        if (no_stream_j)
            my_mean_and_std_dev->mean_j = 0;
        else
            my_mean_and_std_dev->mean_j = channel_stream_j->dumped_IS[i].LS / channel_stream_j->dumped_IS[i].w;
    
        my_mean_and_std_dev->mean_i = channel_dsi_fd->dumped_IS[i].LS / channel_dsi_fd->dumped_IS[i].w;

        my_mean_and_std_dev->std_dev_i = squareRoot(channel_dsi_fd->dumped_IS[i].SS / channel_dsi_fd->dumped_IS[i].w, my_mean_and_std_dev->mean_i * my_mean_and_std_dev->mean_i, 0);
        
        if (no_stream_j)
            my_mean_and_std_dev->std_dev_j = 0;
        else
            my_mean_and_std_dev->std_dev_j = squareRoot(channel_stream_j->dumped_IS[i].SS / channel_stream_j->dumped_IS[i].w, my_mean_and_std_dev->mean_j * my_mean_and_std_dev->mean_j, 0);
        
        //1D

        // Weight
        my_final_package->my_features.packet_features[i].channel_1D.w = channel_dsi_fd->dumped_IS[i].w;
        // Mean = LS/w
        my_final_package->my_features.packet_features[i].channel_1D.mean = my_mean_and_std_dev->mean_i;
        // Standard Deviation = sqrt( abs(SS/w - (LS/w)^2) )
        my_final_package->my_features.packet_features[i].channel_1D.std_dev = my_mean_and_std_dev->std_dev_i;
        
        //2D
        
        // Magnitude = sqrt( mean_i^2 + mean_j^2 )
        my_final_package->my_features.packet_features[i].channel_2D.magnitude = squareRoot(my_mean_and_std_dev->mean_i * my_mean_and_std_dev->mean_i, my_mean_and_std_dev->mean_j * my_mean_and_std_dev->mean_j, 1);
        
        // Radius = sqrt( var_i^2 + var_j^2 )
        my_final_package->my_features.packet_features[i].channel_2D.radius = squareRoot(my_mean_and_std_dev->std_dev_i * my_mean_and_std_dev->std_dev_i, my_mean_and_std_dev->std_dev_j * my_mean_and_std_dev->std_dev_j, 1);
        
        // Approximated Covariance = SRij / (wi + wj)
        if (IP_map_fd_i != NULL) {

            if (IP_map_fd_i->support_dumped_IS[i].SR >= 0) {

                if (no_stream_j)
                    my_final_package->my_features.packet_features[i].channel_2D.aprx_cov = ((unsigned long) IP_map_fd_i->support_dumped_IS[i].SR) / channel_dsi_fd->dumped_IS[i].w;
                else
                    my_final_package->my_features.packet_features[i].channel_2D.aprx_cov = ((unsigned long) IP_map_fd_i->support_dumped_IS[i].SR) / (channel_dsi_fd->dumped_IS[i].w + channel_stream_j->dumped_IS[i].w);
            }
            else {
                if (no_stream_j)
                    my_final_package->my_features.packet_features[i].channel_2D.aprx_cov = ((unsigned long)(-1 * IP_map_fd_i->support_dumped_IS[i].SR)) / channel_dsi_fd->dumped_IS[i].w;
                else
                    my_final_package->my_features.packet_features[i].channel_2D.aprx_cov = ((unsigned long)(-1 * IP_map_fd_i->support_dumped_IS[i].SR)) / (channel_dsi_fd->dumped_IS[i].w + channel_stream_j->dumped_IS[i].w);
                
                my_final_package->my_features.packet_features[i].channel_2D.aprx_cov = -1 * ((long int) my_final_package->my_features.packet_features[i].channel_2D.aprx_cov);
            }
        }
        else if (IP_map_fd_j != NULL) {

            if (IP_map_fd_j->support_dumped_IS[i].SR >= 0) {

                if (no_stream_j)
                    my_final_package->my_features.packet_features[i].channel_2D.aprx_cov = ((unsigned long) IP_map_fd_j->support_dumped_IS[i].SR) / channel_dsi_fd->dumped_IS[i].w;
                else
                    my_final_package->my_features.packet_features[i].channel_2D.aprx_cov = ((unsigned long) IP_map_fd_j->support_dumped_IS[i].SR) / (channel_dsi_fd->dumped_IS[i].w + channel_stream_j->dumped_IS[i].w);
            }
            else {
                if (no_stream_j)
                    my_final_package->my_features.packet_features[i].channel_2D.aprx_cov = ((unsigned long)(-1 * IP_map_fd_j->support_dumped_IS[i].SR)) / channel_dsi_fd->dumped_IS[i].w;
                else
                    my_final_package->my_features.packet_features[i].channel_2D.aprx_cov = ((unsigned long)(-1 * IP_map_fd_j->support_dumped_IS[i].SR)) / (channel_dsi_fd->dumped_IS[i].w + channel_stream_j->dumped_IS[i].w);
                
                my_final_package->my_features.packet_features[i].channel_2D.aprx_cov = -1 * ((long int) my_final_package->my_features.packet_features[i].channel_2D.aprx_cov);
            }
            
        }

        // Correlation Coefficient = Approx.Cov / (std_dev_i * std_dev_j)
        if (my_mean_and_std_dev->std_dev_j == 0 || my_mean_and_std_dev->std_dev_i == 0)
            my_final_package->my_features.packet_features[i].channel_2D.corr_coeff = 0;
        else {
            my_final_package->my_features.packet_features[i].channel_2D.corr_coeff = (my_final_package->my_features.packet_features[i].channel_2D.aprx_cov * 100000) / (my_mean_and_std_dev->std_dev_i * my_mean_and_std_dev->std_dev_j);
            
            if (my_final_package->my_features.packet_features[i].channel_2D.corr_coeff > 100000)
                my_final_package->my_features.packet_features[i].channel_2D.corr_coeff = 100000;

            else if (my_final_package->my_features.packet_features[i].channel_2D.corr_coeff < -100000)
                my_final_package->my_features.packet_features[i].channel_2D.corr_coeff = -100000;
            
        }
    }

    struct packet_infos_and_features_t *entry = packet_and_features_ring.ringbuf_reserve(sizeof(struct packet_infos_and_features_t));

    if (!entry){
        bpf_trace_printk("Not able to store the packet and its features in our ring buffer");
        return XDP_DROP;
    }

    
    __builtin_memcpy(entry, my_final_package, sizeof(struct packet_infos_and_features_t));
    packet_and_features_ring.ringbuf_submit(entry, 0);

    //if (packet_number->counter % 1000000 == 0)
    //    bpf_trace_printk("Counter: %d\n", packet_number->counter);
    
    return XDP_PASS;   // We don't care about the packet
}

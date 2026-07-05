#include <arpa/inet.h>
#include <ctype.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ETHERNET_HEADER_LEN 14
#define ETHER_TYPE_IPV4 0x0800
#define IPV4_MIN_HEADER_LEN 20
#define TCP_MIN_HEADER_LEN 20
#define BYTES_PER_LINE 16

struct ethernet_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

struct ipv4_header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    struct in_addr src_ip;
    struct in_addr dst_ip;
};

struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

static unsigned long packet_number = 0;

static void print_usage(const char *program_name)
{
    printf("Usage: sudo %s <interface> [packet_count] [bpf_filter]\n", program_name);
    printf("Example: sudo %s enp0s3 10 \"tcp\"\n", program_name);
    printf("Example: sudo %s enp0s3 0 \"tcp port 80\"\n", program_name);
    printf("\n");
    printf("packet_count 0 means capture forever.\n");
}

static void print_available_devices(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_devices = NULL;
    pcap_if_t *device = NULL;

    if (pcap_findalldevs(&all_devices, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
        return;
    }

    printf("Available interfaces:\n");
    for (device = all_devices; device != NULL; device = device->next) {
        printf("  %s", device->name);
        if (device->description != NULL) {
            printf(" - %s", device->description);
        }
        printf("\n");
    }

    pcap_freealldevs(all_devices);
}

static void format_mac(const uint8_t mac[6], char *buffer, size_t buffer_size)
{
    snprintf(buffer, buffer_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void print_tcp_flags(uint8_t flags)
{
    int printed = 0;

    printf("[");
    if (flags & 0x01) {
        printf("%sFIN", printed++ ? "," : "");
    }
    if (flags & 0x02) {
        printf("%sSYN", printed++ ? "," : "");
    }
    if (flags & 0x04) {
        printf("%sRST", printed++ ? "," : "");
    }
    if (flags & 0x08) {
        printf("%sPSH", printed++ ? "," : "");
    }
    if (flags & 0x10) {
        printf("%sACK", printed++ ? "," : "");
    }
    if (flags & 0x20) {
        printf("%sURG", printed++ ? "," : "");
    }
    if (flags & 0x40) {
        printf("%sECE", printed++ ? "," : "");
    }
    if (flags & 0x80) {
        printf("%sCWR", printed++ ? "," : "");
    }
    if (!printed) {
        printf("none");
    }
    printf("]");
}

static int looks_like_http(const uint8_t *payload, uint32_t payload_len)
{
    const char *methods[] = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ",
        "PATCH ", "TRACE ", "CONNECT ", "HTTP/"
    };
    size_t i;

    if (payload_len < 4) {
        return 0;
    }

    for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        size_t method_len = strlen(methods[i]);
        if (payload_len >= method_len &&
            memcmp(payload, methods[i], method_len) == 0) {
            return 1;
        }
    }

    return 0;
}

static void print_payload_ascii(const uint8_t *payload, uint32_t payload_len)
{
    uint32_t i;

    for (i = 0; i < payload_len; i++) {
        uint8_t c = payload[i];

        if (c == '\r') {
            printf("\\r");
        } else if (c == '\n') {
            printf("\\n\n");
        } else if (c == '\t') {
            printf("\\t");
        } else if (isprint(c)) {
            putchar(c);
        } else {
            putchar('.');
        }
    }

    if (payload_len == 0 || payload[payload_len - 1] != '\n') {
        printf("\n");
    }
}

static void print_payload_hex_ascii(const uint8_t *payload, uint32_t payload_len)
{
    uint32_t offset;

    for (offset = 0; offset < payload_len; offset += BYTES_PER_LINE) {
        uint32_t line_len = payload_len - offset;
        uint32_t i;

        if (line_len > BYTES_PER_LINE) {
            line_len = BYTES_PER_LINE;
        }

        printf("  %04x  ", offset);
        for (i = 0; i < BYTES_PER_LINE; i++) {
            if (i < line_len) {
                printf("%02x ", payload[offset + i]);
            } else {
                printf("   ");
            }

            if (i == 7) {
                printf(" ");
            }
        }

        printf(" |");
        for (i = 0; i < line_len; i++) {
            uint8_t c = payload[offset + i];
            putchar(isprint(c) ? c : '.');
        }
        printf("|\n");
    }
}

static void packet_handler(u_char *user_data,
                           const struct pcap_pkthdr *packet_header,
                           const u_char *packet)
{
    const struct ethernet_header *eth = NULL;
    const struct ipv4_header *ip = NULL;
    const struct tcp_header *tcp = NULL;
    const uint8_t *payload = NULL;
    char src_mac[18];
    char dst_mac[18];
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char time_buffer[32];
    struct tm *local_time = NULL;
    time_t seconds = packet_header->ts.tv_sec;
    uint32_t ip_header_len = 0;
    uint32_t tcp_header_len = 0;
    uint32_t ip_total_len = 0;
    uint8_t ip_version = 0;
    uint8_t ip_ihl = 0;
    uint32_t tcp_segment_len = 0;
    uint32_t payload_len = 0;
    (void)user_data;

    if (packet_header->caplen < ETHERNET_HEADER_LEN) {
        fprintf(stderr, "Captured packet is too short for Ethernet header.\n");
        return;
    }

    eth = (const struct ethernet_header *)packet;
    if (ntohs(eth->ether_type) != ETHER_TYPE_IPV4) {
        return;
    }

    if (packet_header->caplen < ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN) {
        fprintf(stderr, "Captured packet is too short for IPv4 header.\n");
        return;
    }

    ip = (const struct ipv4_header *)(packet + ETHERNET_HEADER_LEN);
    ip_version = (ip->version_ihl >> 4) & 0x0f;
    ip_ihl = ip->version_ihl & 0x0f;

    if (ip_version != 4 || ip->protocol != IPPROTO_TCP) {
        return;
    }

    ip_header_len = (uint32_t)ip_ihl * 4;
    if (ip_header_len < IPV4_MIN_HEADER_LEN) {
        fprintf(stderr, "Invalid IPv4 header length: %u bytes.\n", ip_header_len);
        return;
    }

    if (packet_header->caplen < ETHERNET_HEADER_LEN + ip_header_len + TCP_MIN_HEADER_LEN) {
        fprintf(stderr, "Captured packet is too short for TCP header.\n");
        return;
    }

    ip_total_len = ntohs(ip->total_len);
    if (ip_total_len < ip_header_len + TCP_MIN_HEADER_LEN) {
        fprintf(stderr, "Invalid IPv4 total length: %u bytes.\n", ip_total_len);
        return;
    }

    tcp = (const struct tcp_header *)(packet + ETHERNET_HEADER_LEN + ip_header_len);
    tcp_header_len = (uint32_t)((tcp->data_offset_reserved >> 4) & 0x0f) * 4;
    if (tcp_header_len < TCP_MIN_HEADER_LEN) {
        fprintf(stderr, "Invalid TCP header length: %u bytes.\n", tcp_header_len);
        return;
    }

    if (ip_total_len < ip_header_len + tcp_header_len) {
        fprintf(stderr, "IPv4 total length is smaller than header lengths.\n");
        return;
    }

    tcp_segment_len = ip_total_len - ip_header_len;
    payload_len = tcp_segment_len - tcp_header_len;
    payload = packet + ETHERNET_HEADER_LEN + ip_header_len + tcp_header_len;

    if (packet_header->caplen < ETHERNET_HEADER_LEN + ip_header_len + tcp_header_len + payload_len) {
        payload_len = packet_header->caplen - ETHERNET_HEADER_LEN - ip_header_len - tcp_header_len;
    }

    packet_number++;
    local_time = localtime(&seconds);
    if (local_time != NULL) {
        strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", local_time);
    } else {
        snprintf(time_buffer, sizeof(time_buffer), "unknown-time");
    }

    format_mac(eth->src_mac, src_mac, sizeof(src_mac));
    format_mac(eth->dst_mac, dst_mac, sizeof(dst_mac));
    inet_ntop(AF_INET, &ip->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip->dst_ip, dst_ip, sizeof(dst_ip));

    printf("\n================ Packet #%lu ================\n", packet_number);
    printf("Captured Time     : %s.%06ld\n", time_buffer, (long)packet_header->ts.tv_usec);
    printf("Captured Length   : %u bytes\n", packet_header->caplen);
    printf("Original Length   : %u bytes\n", packet_header->len);
    printf("\n");

    printf("[Ethernet Header]\n");
    printf("  Source MAC      : %s\n", src_mac);
    printf("  Destination MAC : %s\n", dst_mac);
    printf("  EtherType       : 0x%04x (IPv4)\n", ntohs(eth->ether_type));
    printf("\n");

    printf("[IP Header]\n");
    printf("  Source IP       : %s\n", src_ip);
    printf("  Destination IP  : %s\n", dst_ip);
    printf("  Header Length   : %u bytes\n", ip_header_len);
    printf("  Total Length    : %u bytes\n", ip_total_len);
    printf("  TTL             : %u\n", ip->ttl);
    printf("  Protocol        : %u (TCP)\n", ip->protocol);
    printf("\n");

    printf("[TCP Header]\n");
    printf("  Source Port     : %u\n", ntohs(tcp->src_port));
    printf("  Destination Port: %u\n", ntohs(tcp->dst_port));
    printf("  Header Length   : %u bytes\n", tcp_header_len);
    printf("  Sequence Number : %u\n", ntohl(tcp->seq_num));
    printf("  ACK Number      : %u\n", ntohl(tcp->ack_num));
    printf("  Flags           : ");
    print_tcp_flags(tcp->flags);
    printf("\n");
    printf("  Window Size     : %u\n", ntohs(tcp->window));
    printf("\n");

    printf("[HTTP/Application Message]\n");
    printf("  Payload Length  : %u bytes\n", payload_len);
    if (payload_len == 0) {
        printf("  No application data in this TCP packet.\n");
    } else if (looks_like_http(payload, payload_len)) {
        printf("  Looks like HTTP text. Printable message:\n");
        print_payload_ascii(payload, payload_len);
    } else {
        printf("  Not plain HTTP or not enough evidence. Hex/ASCII dump:\n");
        print_payload_hex_ascii(payload, payload_len);
    }

    fflush(stdout);
}

int main(int argc, char *argv[])
{
    const char *interface_name = NULL;
    const char *filter_expression = "tcp";
    int packet_count = -1;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;
    pcap_t *handle = NULL;
    struct bpf_program compiled_filter;

    if (argc < 2) {
        print_usage(argv[0]);
        print_available_devices();
        return EXIT_FAILURE;
    }

    interface_name = argv[1];

    if (argc >= 3) {
        packet_count = atoi(argv[2]);
        if (packet_count < 0) {
            fprintf(stderr, "packet_count must be 0 or a positive integer.\n");
            return EXIT_FAILURE;
        }
    }

    if (argc >= 4) {
        filter_expression = argv[3];
    }

    if (packet_count == 0) {
        packet_count = -1;
    }

    if (pcap_lookupnet(interface_name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "pcap_lookupnet warning: %s\n", errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "This program expects Ethernet packets (DLT_EN10MB).\n");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    if (pcap_compile(handle, &compiled_filter, filter_expression, 0, net) == -1) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    if (pcap_setfilter(handle, &compiled_filter) == -1) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&compiled_filter);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    printf("Interface : %s\n", interface_name);
    printf("Filter    : %s\n", filter_expression);
    printf("Count     : %s\n", packet_count == -1 ? "forever" : argv[2]);
    printf("Press Ctrl+C to stop when running forever.\n");

    if (pcap_loop(handle, packet_count, packet_handler, NULL) == -1) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&compiled_filter);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    pcap_freecode(&compiled_filter);
    pcap_close(handle);

    return EXIT_SUCCESS;
}

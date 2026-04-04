#include <sys/socket.h>
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"

char *selected_interface = NULL;
int filter_port = 0;
int show_help_flag = 0;
int packet_count = 0;
volatile sig_atomic_t stop_sniffing = 0;

void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\n\n" COLOR_YELLOW "\n[*] Stopping capture... Total packets: %d\n" COLOR_RESET, packet_count);
        stop_sniffing = 1;
    }
}

char* select_interface() {
    struct ifaddrs *ifaddr, *ifa;
    int choice = 0;
    int interface_count = 0;
    struct ifaddrs **interfaces = NULL;
    
    if(getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return NULL;
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET) {
            interface_count++;
        }
    }
    
    if (interface_count == 0) {
        printf("No network interfaces found.\n");
        freeifaddrs(ifaddr);
        return NULL;
    }
    
    interfaces = malloc(interface_count * sizeof(struct ifaddrs*));
    if (!interfaces) {
        perror("malloc");
        freeifaddrs(ifaddr);
        return NULL;
    }
    
    int index = 0;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET) {
            interfaces[index++] = ifa;
        }
    }
    
    printf("\n" COLOR_CYAN "Available network interfaces:\n" COLOR_RESET);
    for (int i = 0; i < interface_count; i++) {
        struct sockaddr_in *addr = (struct sockaddr_in*)interfaces[i]->ifa_addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr->sin_addr), ip, INET_ADDRSTRLEN);
        
        printf("%d. %s (IP: %s", i + 1, interfaces[i]->ifa_name, ip);
        
        if (interfaces[i]->ifa_flags & IFF_UP)
            printf(", UP");
        if (interfaces[i]->ifa_flags & IFF_RUNNING)
            printf(", RUNNING");
        printf(")\n");
    }
    
    printf("\n" COLOR_YELLOW "Select interface (1-%d): " COLOR_RESET, interface_count);
    scanf("%d", &choice);
    
    if (choice < 1 || choice > interface_count) {
        printf("Invalid choice.\n");
        free(interfaces);
        freeifaddrs(ifaddr);
        return NULL;
    }
    
    char *selected = malloc(IFNAMSIZ);
    if (selected) {
        strcpy(selected, interfaces[choice - 1]->ifa_name);
        printf(COLOR_GREEN "\nSelected interface: %s\n" COLOR_RESET, selected);
    }
    
    free(interfaces);
    freeifaddrs(ifaddr);
    return selected;
}

void use_def_in() {
    printf("Network interface not provided, using default...\n");
    
    struct ifaddrs *ifaddr, *ifa;
    
    if(getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr != NULL && 
            ifa->ifa_addr->sa_family == AF_INET &&
            strcmp(ifa->ifa_name, "lo") != 0 &&
            (ifa->ifa_flags & IFF_UP)) {
            
            selected_interface = malloc(IFNAMSIZ);
            if (selected_interface) {
                strcpy(selected_interface, ifa->ifa_name);
                printf(COLOR_GREEN "Using default interface: %s\n" COLOR_RESET, selected_interface);
            }
            break;
        }
    }
    
    freeifaddrs(ifaddr);
    
    if (!selected_interface) {
        printf("No suitable interface found. Using loopback.\n");
        selected_interface = malloc(IFNAMSIZ);
        if (selected_interface) {
            strcpy(selected_interface, "lo");
        }
    }
}

void usage(){
    printf("Usage: sniffer -i [INTERFACE] [-p PORT] [-h]\n");
}

void help_menu(){
    printf(COLOR_CYAN "\n[</>] Network Sniffer - Developer: r31v14n\n\n" COLOR_RESET);
    printf("    " COLOR_YELLOW "Network Sniffer Help" COLOR_RESET "    \n");
    printf("Usage: sniffer [OPTIONS]\n\n");
    printf("OPTIONS:\n");
    printf("  -i [INTERFACE]     Specify network interface to sniff\n");
    printf("  -i                 Interactive interface selection\n");
    printf("  -p [PORT]          Filter packets by port (TCP/UDP)\n");
    printf("  -h, --help         Show this help message\n\n");
    printf("EXAMPLES:\n");
    printf("  sniffer -i eth0              Sniff on eth0 interface\n");
    printf("  sniffer -i wlan0 -p 443      Sniff only HTTPS traffic on wlan0\n");
    printf("  sniffer -i                   Select interface interactively\n");
    printf("  sniffer -p 80                Use default interface, filter port 80\n\n");
    printf(COLOR_RED "  Requires root privileges to create raw sockets\n" COLOR_RESET);
}

int create_raw_socket(const char *interface) {
    int sockfd;
    struct sockaddr_ll sll;
    struct ifreq ifr;
    
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sockfd);
        return -1;
    }
    
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    
    if (bind(sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }
    
    printf(COLOR_GREEN "Raw socket created and bound to interface: %s\n" COLOR_RESET, interface);
    if (filter_port) {
        printf(COLOR_YELLOW "Filtering packets on port: %d\n" COLOR_RESET, filter_port);
    }
    return sockfd;
}

const char* get_protocol_name(uint8_t protocol) {
    switch(protocol) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_RAW: return "RAW";
        default: return "OTHER";
    }
}

void print_packet_info(const char *src_ip, const char *dst_ip, 
                       uint16_t src_port, uint16_t dst_port,
                       const char *protocol, size_t size) {
    time_t now;
    time(&now);
    struct tm *tm_info = localtime(&now);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    
    printf("[%s] ", time_str);
    
    if (strcmp(protocol, "TCP") == 0)
        printf(COLOR_GREEN);
    else if (strcmp(protocol, "UDP") == 0)
        printf(COLOR_YELLOW);
    else
        printf(COLOR_MAGENTA);
    
    printf("%s", protocol);
    printf(COLOR_RESET);
    printf(" %s:%d ", src_ip, src_port);
    printf(COLOR_BLUE "→" COLOR_RESET);
    printf(" %s:%d ", dst_ip, dst_port);
    printf(COLOR_RED "[%zu bytes]" COLOR_RESET, size);
    printf("\n");
}

void sniff_packets(int sockfd) {
    char buffer[65536];
    
    printf("\n" COLOR_GREEN "Starting packet capture... Press Ctrl+C to stop.\n\n" COLOR_RESET);
    
    while (!stop_sniffing) {
        ssize_t packet_size = recv(sockfd, buffer, sizeof(buffer), 0);
        if (packet_size > 0) {
            packet_count++;
            
            struct ether_header *eth = (struct ether_header*)buffer;
            uint16_t eth_type = ntohs(eth->ether_type);
            
            if (eth_type == ETHERTYPE_IP) {
                struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ether_header));
                char src_ip[INET_ADDRSTRLEN];
                char dst_ip[INET_ADDRSTRLEN];
                
                inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);
                
                int ip_header_len = ip->ihl * 4;
                uint16_t src_port = 0, dst_port = 0;
                const char *proto_name = get_protocol_name(ip->protocol);
                int should_print = 1;
                
                if (ip->protocol == IPPROTO_TCP && packet_size >= (ssize_t)(sizeof(struct ether_header) + ip_header_len + sizeof(struct tcphdr))) {
                    struct tcphdr *tcp = (struct tcphdr*)(buffer + sizeof(struct ether_header) + ip_header_len);
                    src_port = ntohs(tcp->source);
                    dst_port = ntohs(tcp->dest);
                    if (filter_port && src_port != filter_port && dst_port != filter_port) {
                        should_print = 0;
                    }
                } 
                else if (ip->protocol == IPPROTO_UDP && packet_size >= (ssize_t)(sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr))) {
                    struct udphdr *udp = (struct udphdr*)(buffer + sizeof(struct ether_header) + ip_header_len);
                    src_port = ntohs(udp->source);
                    dst_port = ntohs(udp->dest);
                    if (filter_port && src_port != filter_port && dst_port != filter_port) {
                        should_print = 0;
                    }
                }
                else if (filter_port) {
                    should_print = 0;
                }
                
                if (should_print) {
                    if (src_port == 0 && dst_port == 0) {
                        // ICMP 
                        printf(COLOR_MAGENTA "[%s] %s %s -> %s [%zu bytes]\n" COLOR_RESET, 
                               proto_name, src_ip, dst_ip, packet_size);
                    } else {
                        print_packet_info(src_ip, dst_ip, src_port, dst_port, proto_name, packet_size);
                    }
                }
            }
            else if (eth_type == ETHERTYPE_ARP) {
                if (!filter_port) {
                    printf(COLOR_MAGENTA "[ARP] frame [%zu bytes]\n" COLOR_RESET, packet_size);
                }
            }
            
            if (packet_count % 100 == 0 && packet_count > 0) {
                printf(COLOR_YELLOW "\r[*] Captured %d packets so far..." COLOR_RESET, packet_count);
                fflush(stdout);
            }
        } else if (packet_size == 0) {
            printf("Connection closed\n");
            break;
        } else {
            if (errno != EINTR && errno != EAGAIN) {
                perror("recv");
            }
            break;
        }
    }
}

int main(int argc, char **argv){
    int sockfd;
    
    signal(SIGINT, signal_handler);
    
    for (int i = 1; i < argc; i++) {
        if (strcmp("-h", argv[i]) == 0 || strcmp("--help", argv[i]) == 0) {
            help_menu();
            return 0;
        }
        else if (strcmp("-i", argv[i]) == 0 && i + 1 < argc && argv[i+1][0] != '-') {
            selected_interface = malloc(IFNAMSIZ);
            if (selected_interface) {
                strcpy(selected_interface, argv[i+1]);
                printf(COLOR_GREEN "Using specified interface: %s\n" COLOR_RESET, selected_interface);
            }
            i++;
        }
        else if (strcmp("-i", argv[i]) == 0 && (i + 1 >= argc || argv[i+1][0] == '-')) {
            selected_interface = select_interface();
            if (!selected_interface) {
                return 1;
            }
        }
        else if (strcmp("-p", argv[i]) == 0 && i + 1 < argc) {
            filter_port = atoi(argv[i+1]);
            if (filter_port <= 0 || filter_port > 65535) {
                fprintf(stderr, COLOR_RED "Invalid port number\n" COLOR_RESET);
                return 1;
            }
            printf(COLOR_YELLOW "Will filter packets on port: %d\n" COLOR_RESET, filter_port);
            i++;
        }
        else if (argv[i][0] == '-') {
            fprintf(stderr, COLOR_RED "Unknown option: %s\n" COLOR_RESET, argv[i]);
            usage();
            return 1;
        }
    }
    
    if (!selected_interface) {
        use_def_in();
        if (!selected_interface) {
            fprintf(stderr, "Failed to select interface\n");
            return 1;
        }
    }
    
    sockfd = create_raw_socket(selected_interface);
    if (sockfd < 0) {
        fprintf(stderr, "Failed to create socket on interface %s\n", selected_interface);
        free(selected_interface);
        return 1;
    }
    
    sniff_packets(sockfd);
    
    close(sockfd);
    free(selected_interface);
    return 0;
}

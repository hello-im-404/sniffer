#include <sys/socket.h>
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <errno.h>

char *selected_interface = NULL;

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
    
    printf("\nAvailable network interfaces:\n");
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
    
    printf("\nSelect interface (1-%d): ", interface_count);
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
        printf("\nSelected interface: %s\n", selected);
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
                printf("Using default interface: %s\n", selected_interface);
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
    printf("Usage: sniffer -i [INTERFACE] .. -h [HELP_MENU]\n");
}

void help_menu(){
	printf("[ </> ] Developer: r31v14n\n\n");
    printf("\n    Network Sniffer Help    \n");
    printf("Usage: sniffer [OPTIONS]\n\n");
    printf("OPTIONS:\n");
    printf("  -i [INTERFACE]     Specify network interface to sniff\n");
    printf("  -i                 Interactive interface selection\n");
    printf("  -h, --help         Show this help message\n\n");
    printf("EXAMPLES:\n");
    printf("  sniffer -i eth0    Sniff on eth0 interface\n");
    printf("  sniffer -i         Select interface interactively\n");
    printf("  sniffer            Use default interface\n\n");
    printf("  Requires root privileges to create raw sockets\n");
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
    
    printf("Raw socket created and bound to interface: %s\n", interface);
    return sockfd;
}

void sniff_packets(int sockfd) {
    char buffer[65536];
    int packet_count = 0;
    
    printf("\nStarting packet capture... Press Ctrl+C to stop.\n\n");
    
    while (1) {
        ssize_t packet_size = recv(sockfd, buffer, sizeof(buffer), 0);
        if (packet_size > 0) {
            packet_count++;
            printf("Packet #%d: Received %zd bytes\n", packet_count, packet_size);
            
            struct ether_header *eth = (struct ether_header*)buffer;
            printf("  Ethernet type: 0x%04x\n", ntohs(eth->ether_type));
            
            if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
                struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ether_header));
                char src_ip[INET_ADDRSTRLEN];
                char dst_ip[INET_ADDRSTRLEN];
                
                inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);
                
                printf("  IP: %s -> %s\n", src_ip, dst_ip);
            }
        } else if (packet_size == 0) {
            printf("Connection closed\n");
            break;
        } else {
            if (errno != EINTR) {
                perror("recv");
            }
            break;
        }
    }
}

int main(int argc, char **argv){
    int sockfd;
    
    if(argc < 2) {
        usage();
        return 1;
    }

    if(strcmp("-h", argv[1]) == 0 || strcmp("--help", argv[1]) == 0){
        help_menu();
        return 0;
    }

    if (argc >= 3 && strcmp("-i", argv[1]) == 0) {
        selected_interface = malloc(IFNAMSIZ);
        if (selected_interface) {
            strcpy(selected_interface, argv[2]);
            printf("Using specified interface: %s\n", selected_interface);
        } else {
            perror("malloc");
            return 1;
        }
    } else if (argc >= 2 && strcmp("-i", argv[1]) == 0 && argc < 3) {
        selected_interface = select_interface();
        if (!selected_interface) {
            return 1;
        }
    } else {
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

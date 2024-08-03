#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>


// Function to convert an IPv4 address string to a 32-bit integer
uint32_t ip_to_int(const char *ip) {
    struct in_addr addr;
    inet_pton(AF_INET, ip, &addr);
    return ntohl(addr.s_addr);
}

// Function to convert a 32-bit integer to an IPv4 address string
void int_to_ip(uint32_t ip, char *buffer) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN);
}

// Function to find the largest CIDR block within the given range
void cidr_range(uint32_t start_ip, uint32_t end_ip) {
    while (start_ip <= end_ip) {
        uint32_t mask = 32;

        // Determine the size of the largest block
        while (mask > 0) {
            uint32_t subnet_mask = (1 << (32 - mask)) - 1;
            if ((start_ip & ~subnet_mask) != start_ip) {
                break;
            }
            if ((start_ip | subnet_mask) > end_ip) {
                break;
            }
            mask--;
        }

        // Print the CIDR block
        char ip_str[INET_ADDRSTRLEN];
        int_to_ip(start_ip, ip_str);
        printf("%s/%d\n", ip_str, mask + 1);

        // Move to the next block
        start_ip += (1 << (32 - (mask + 1)));
    }
}

int main() {
    const char *start_ip_str = "192.168.0.4";
    const char *end_ip_str = "192.168.255.2";

    uint32_t start_ip = ip_to_int(start_ip_str);
    uint32_t end_ip = ip_to_int(end_ip_str);

    cidr_range(start_ip, end_ip);

    return 0;
}
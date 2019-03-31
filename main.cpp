#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#define ETHERTYPE_IP 0x0800
#define IP_TCP 0x06

struct eth{
    unsigned char ether_dhost[6];
    unsigned char ether_shost[6];//uint8_t 6byte
    unsigned short ether_type;//uint16_t 2byte
};

struct ip{
    unsigned char ihl:4;
    unsigned char ip_version:4;
    unsigned char ip_tos;
    unsigned short ip_total_length;
    unsigned short ip_id;
    unsigned short ip_frag_offset;
    unsigned char ip_ttl;
    unsigned char ip_protocol;
    unsigned short ip_checksum;
    unsigned char ip_sip[4];
    unsigned char ip_dip[4];
};

struct tcp{
    unsigned short source_port;
    unsigned short dest_port;
    unsigned int sequence;
    unsigned int acknowledge;
    unsigned char ns:1;
    unsigned char reserved_part1:3;
    unsigned char data_offset:4;
    unsigned char fin:1;
    unsigned char syn:1;
    unsigned char rst:1;
    unsigned char psh:1;
    unsigned char ack:1;
    unsigned char urg:1;
    unsigned char ecn:1;
    unsigned char cwr:1;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
};
//struct
void print_eth (const unsigned char *data);
int print_ip(const unsigned char *data);
int print_tcp(const unsigned char *data);
void data(const unsigned char *data);

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
    int offset=0;
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        //printf("%x bytes captured\n", header->caplen);

        print_eth(packet);
        packet = packet + 14;
        offset = print_ip(packet);
        packet = packet + offset;
        offset = print_tcp(packet);
        packet = packet + offset;
        data(packet);
        int b = 14 + offset*2;
        int a = (header->caplen)-b;
        printf("http length:%d\n",a);
        break;
    }

    pcap_close(handle);
    return 0;
}

void print_eth(const unsigned char *data){
    struct eth *eh = (struct eth *)data;
    unsigned short ether_type = ntohs(eh->ether_type);
    printf("==========MAC==========\n\n");
    if(ether_type == ETHERTYPE_IP){
        printf("ether_type: ip\n");
        printf("Smac:%02x:%02x:%02x:%02x:%02x:%02x\n"
               ,eh->ether_shost[0]
                ,eh->ether_shost[1]
                ,eh->ether_shost[2]
                ,eh->ether_shost[3]
                ,eh->ether_shost[4]
                ,eh->ether_shost[5]);

        printf("Dmac:%02x:%02x:%02x:%02x:%02x:%02x\n\n"
               ,eh->ether_dhost[0]
                ,eh->ether_dhost[1]
                ,eh->ether_dhost[2]
                ,eh->ether_dhost[3]
                ,eh->ether_dhost[4]
                ,eh->ether_dhost[5]);
    }
    else {
        printf("error\n");
    }

}

int print_ip(const unsigned char *data){
    struct ip *ih = (struct ip *)data;
    printf("==========IP==========\n\n");

    if(ih->ip_protocol == IP_TCP){
        printf("ip_protocol:tcp\n");
        printf("Sip:%d.%d.%d.%d\n",
               ih->ip_sip[0],
                ih->ip_sip[1],
                ih->ip_sip[2],
                ih->ip_sip[3]);

        printf("Dip:%d.%d.%d.%d\n\n",
               ih->ip_dip[0],
                ih->ip_dip[1],
                ih->ip_dip[2],
                ih->ip_dip[3]);
        return ih->ihl*4;
    }
    else printf("error\n");
}

int print_tcp(const unsigned char *data){
    struct tcp *th =(struct tcp *)data;

    printf("==========PORT==========\n\n");

    printf("Sport: %d\n",ntohs(th->source_port));
    printf("Dport: %d\n\n",ntohs(th->dest_port));
    return th->data_offset*4;
}

void data(const unsigned char *data){

    printf("==========DATA==========\n");
    printf("DATA:");
    for(int i=0; i<16 ;i++){
        printf("%c",*data);
        data++;
    }
    printf("\n");
}

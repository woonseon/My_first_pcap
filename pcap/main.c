#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>

#include <errno.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

int main(int argc, char *argv[])
{
    // ethernet headr struct
    struct ether_header *eth;
    // ip header struct
    struct ip *iph;
    // tcp header struct
    struct tcphdr *tcph;

    pcap_t *handle;			/* Session handle */
    char *dev;			// network device name
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    const u_char *pkt_data;   //
    unsigned short ether_type;
    struct pcap_pkthdr *header;

    /* Define the device */
    dev = pcap_lookupdev(errbuf);   // get network device name
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    printf("DEV: %s\n", dev);   // network device name

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    // grab packet
    while(1)
    {
        //pkt_data = NULL;
        pcap_next_ex(handle, &header, &pkt_data);
        eth = (struct ether_header *)pkt_data;

        // IP 헤더를 가져오기 위해서
        // 이더넷 헤더 크기만큼 offset 한다.
        pkt_data += sizeof(struct ether_header);

        ether_type = ntohs(eth->ether_type);

        // ip packet
        if (ether_type == ETHERTYPE_IP)
        {
            printf("---------------ether packet---------------\n");
            printf("ether type: %hd\n", ether_type);
            printf("Src Mac: ");
            for (int i=0; i<=5; i++)
                printf("%.2X ", eth->ether_shost[i]);
            printf("\nDst Mac: ");
            for (int i=0; i<=5; i++)
                printf("%.2X ", eth->ether_dhost[i]);
            printf("\n");

            // IP 헤더에서 데이타 정보를 출력한다.
            iph = (struct ip *)pkt_data;
            printf("---------------ip packet---------------\n");
            printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
            printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));

            // if TCP
            if (iph->ip_p == IPPROTO_TCP)
            {
                pkt_data += sizeof(struct ip);
                tcph = (struct tcphdr *)pkt_data;
                printf("---------------Port Number---------------\n");
                printf("Src Port : %d\n" , ntohs(tcph->source));
                printf("Dst Port : %d\n" , ntohs(tcph->dest));
            }

            // else data
            unsigned int data_length = header->len - sizeof(struct ether_header) - sizeof(struct ip) - sizeof(struct tcphdr);
            printf("---------------else data---------------\n");
            printf("data length = %d\n", data_length);
            for (int i=0; i<data_length; i++)
                printf("%.2X ", pkt_data[i]);
            printf("\n=========================================\n");
            printf("\n");
        }
    }
    pcap_close(handle);
    return(0);
}

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>

#define	DEFAULT_DOMAIN	AF_INET6
//#define	DEFAULT_DOMAIN	AF_INET

void (*dump_protocol)(void *phdr) = NULL;

int
raw_socket()
{
	int	fd;
	int	ret;
	int	on = 1;
	//int	inettype = (DEFAULT_DOMAIN == AF_INET6) ? AF_INET6 : AF_INET;
	int	proto = (DEFAULT_DOMAIN == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IP;
	int	protocol = IPPROTO_ICMP;

	if (DEFAULT_DOMAIN == AF_INET6) {
		protocol = IPPROTO_ICMPV6;
	}

	fd = socket(DEFAULT_DOMAIN, SOCK_RAW, protocol);
	//fd = socket(PF_PACKET, SOCK_RAW, ETH_P_ALL);
	if (fd < 0) {
		perror("socket:");
		return fd;
	}

	ret = setsockopt(fd, proto, IP_HDRINCL, &on, sizeof(int));
/*	ret = setsockopt(fd, proto, IPV6_HDRINCL, &on, sizeof(int)); 
	if (ret < 0) {
		perror("setsockopt:");
		close(fd);
		return ret;
	}  */
	return fd;
}

int
bind_interface(int sfd, char *ifaddr)
{
	int index;
	struct	sockaddr_in	sockaddr;
	struct	sockaddr_in6	sock6addr;
	//index = if_nametoindex(ifname);
	if (index == 0) {
		perror("lo nametoindex");
		return -1;
	}
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = 9090;
	sockaddr.sin_addr.s_addr = inet_addr(ifaddr);
	if (DEFAULT_DOMAIN == AF_INET6) {
		sock6addr.sin6_family = DEFAULT_DOMAIN;
		sock6addr.sin6_port = htons(9090);
		sock6addr.sin6_addr = in6addr_any;
		if (bind(sfd, (struct sockaddr *)&sock6addr, sizeof(sock6addr)) < 0) {
			perror("bind6 error:");
			return -1;
		}
	} else {	
		if (bind(sfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
			perror("bind error:");
			return -1;
		}
	}
	return 0;
}

#define HEADER_SIZE (sizeof(struct iphdr) + sizeof(struct udphdr))

void
dump_icmp_hdr(void *ihdr)
{
	struct icmphdr *hdr = (struct icmphdr *)ihdr;
	printf("DUMP ICMP\n");
	printf("==========\n");
	printf("icmp->type %x\n", hdr->type);
	printf("icmp->code %x\n", hdr->code);
	printf("icmp->checksum %x\n", hdr->checksum);
	if (hdr->type == ICMP_ECHOREPLY || hdr->type == ICMP_ECHO) {
		printf("icmp->un.echo.id %x\n", hdr->un.echo.id);
		printf("icmp->un.echo.sequence %x\n", hdr->un.echo.sequence);
	}
}

void
dump_tcp_hdr(void *tcphdr)
{
	printf("TCP HEADER\n");
}

void
dump_udp_hdr(void *udphdr)
{
	printf("TCP HEADER\n");
}

void
dump_ipv6hdr(struct ipv6hdr *ihdr)
{
	char ipaddr[256];

	printf("IPv6 HEADER\n");
	printf("==============\n");
	printf("ipv6hdr->version %d\n", ihdr->version);
	printf("ipv6hdr->priority %d\n", ihdr->priority);
	printf("ipv6hdr->flow_lbl %d\n", ihdr->priority);
	printf("ipv6hdr->payload_len %d\n", ihdr->payload_len);
	printf("ipv6hdr->nexthdr %d\n", ihdr->nexthdr);

	inet_ntop(AF_INET6, &ihdr->saddr, ipaddr, sizeof(ipaddr));
	printf("ipv6hdr->source_address %s\n", ipaddr);
	inet_ntop(AF_INET6, &ihdr->daddr, ipaddr, sizeof(ipaddr));
	printf("ipv6hdr->source_address %s\n", ipaddr);
}
void
dump_iphdr(struct iphdr *ihdr)
{
	char ipaddr[256];
/*
	printf("sizeof eth hdr %d\n", sizeof(struct ethhdr));
	printf("sizeof ip hdr %d\n", sizeof(struct iphdr));
	printf("sizeof tcp hdr %d\n", sizeof(struct tcphdr));
	printf("sizeof udp hdr %d\n", sizeof(struct udphdr)); */

	printf("IP HEADER\n");
	printf("==========\n");

	printf("ihdr->version %d\n", (uint8_t)ihdr->version);
	printf("ihdr->ihl %d\n", (uint8_t)ihdr->ihl);
	printf("ihdr->tos(type of service) %d\n", (uint8_t)ihdr->tos);
	printf("ihdr->tot(total length) %d\n", (uint8_t)ihdr->tot_len);
	printf("ihdr->id(Identification) %d\n", (uint8_t)ihdr->id);
	printf("ihdr->frag_off(fragmentation off) %d\n", (uint8_t)ihdr->frag_off);
	printf("ihdr->ttl(Time to live) %d\n", (uint8_t)ihdr->ttl);
	printf("ihdr->protocol(Protocol) %d\n", (uint8_t)ihdr->protocol);
	printf("ihdr->check(Checksum) %d\n", (uint8_t)ihdr->check);

	//saddr.sin_addr.s_addr = ihdr->saddr;	
	//daddr.sin_addr.s_addr = ihdr->daddr;	
	inet_ntop(AF_INET, &ihdr->saddr, ipaddr, sizeof(ipaddr));
	printf("ihdr->source_address %s\n", ipaddr);
	inet_ntop(AF_INET, &ihdr->daddr, ipaddr, sizeof(ipaddr));
	printf("ihdr->destination_address %s\n", ipaddr);

	switch (ihdr->protocol) {
	case IPPROTO_ICMP:
		dump_protocol = dump_icmp_hdr;
		break;
	case IPPROTO_TCP:
		dump_protocol = dump_tcp_hdr;
		break;
	case IPPROTO_UDP:
		dump_protocol = dump_udp_hdr;
		break;
	default:
		printf("Unsupported protocol: %x\n", ihdr->protocol);
		break;
	}
}

int
main()
{
	int sockfd;
	int bytes=0;
	int i;
	char buffer[256];
	struct	iphdr *ihdr;

	sockfd = raw_socket();
	if (sockfd < 0) {
		perror("raw_socket() failed:");
		return sockfd;
	}
	//bind_interface(sockfd, "127.0.0.1");

	while (1) {
		bytes = recv(sockfd, buffer, sizeof(buffer), 0);
		if (bytes <= HEADER_SIZE) {
			sleep(1);
			printf("HEADER_SIZE \n");
			continue;
		}
		if (DEFAULT_DOMAIN == AF_INET) {
			dump_iphdr((struct iphdr *)buffer);
			//ihdr = (struct iphdr *)buffer;
			dump_protocol(buffer+sizeof(struct iphdr));
		} else {
			dump_ipv6hdr((struct ipv6hdr *)buffer);
		}
		//printf("bytes read %d\n", bytes);
/*		for (i = 0; i < bytes; i++) {
			printf("%02X ", buffer[i-1]);
			if (i && !(i%16)) {
				printf("\n");
			}
		} */
		sleep(1);
	}
	close(sockfd);
	return 9;
}

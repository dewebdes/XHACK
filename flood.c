/*
	Raw TCP packets
	Silver Moon (m00n.silv3r@gmail.com)
*/
#include&lt;stdio.h&gt;	//for printf
#include&lt;string.h&gt; //memset
#include&lt;sys/socket.h&gt;	//for socket ofcourse
#include&lt;stdlib.h&gt; //for exit(0);
#include&lt;errno.h&gt; //For errno - the error number
#include&lt;netinet/tcp.h&gt;	//Provides declarations for tcp header
#include&lt;netinet/ip.h&gt;	//Provides declarations for ip header

/* 
	96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

/*
	Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes&gt;1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&amp;oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum&gt;&gt;16)+(sum &amp; 0xffff);
	sum = sum + (sum&gt;&gt;16);
	answer=(short)~sum;
	
	return(answer);
}

int main (void)
{
	//Create a raw socket
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
	
	if(s == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror(&quot;Failed to create socket&quot;);
		exit(1);
	}
	
	//Datagram to represent the packet
	char datagram[4096] , source_ip[32] , *data , *pseudogram;
	
	//zero out the packet buffer
	memset (datagram, 0, 4096);
	
	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;
	struct pseudo_header psh;
	
	//Data part
	data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
	strcpy(data , &quot;ABCDEFGHIJKLMNOPQRSTUVWXYZ&quot;);
	
	//some address resolution
	strcpy(source_ip , &quot;192.168.1.2&quot;);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	sin.sin_addr.s_addr = inet_addr (&quot;1.2.3.4&quot;);
	
	//Fill in the IP Header
	iph-&gt;ihl = 5;
	iph-&gt;version = 4;
	iph-&gt;tos = 0;
	iph-&gt;tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
	iph-&gt;id = htonl (54321);	//Id of this packet
	iph-&gt;frag_off = 0;
	iph-&gt;ttl = 255;
	iph-&gt;protocol = IPPROTO_TCP;
	iph-&gt;check = 0;		//Set to 0 before calculating checksum
	iph-&gt;saddr = inet_addr ( source_ip );	//Spoof the source ip address
	iph-&gt;daddr = sin.sin_addr.s_addr;
	
	//Ip checksum
	iph-&gt;check = csum ((unsigned short *) datagram, iph-&gt;tot_len);
	
	//TCP Header
	tcph-&gt;source = htons (1234);
	tcph-&gt;dest = htons (80);
	tcph-&gt;seq = 0;
	tcph-&gt;ack_seq = 0;
	tcph-&gt;doff = 5;	//tcp header size
	tcph-&gt;fin=0;
	tcph-&gt;syn=1;
	tcph-&gt;rst=0;
	tcph-&gt;psh=0;
	tcph-&gt;ack=0;
	tcph-&gt;urg=0;
	tcph-&gt;window = htons (5840);	/* maximum allowed window size */
	tcph-&gt;check = 0;	//leave checksum 0 now, filled later by pseudo header
	tcph-&gt;urg_ptr = 0;
	
	//Now the TCP checksum
	psh.source_address = inet_addr( source_ip );
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &amp;psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));
	
	tcph-&gt;check = csum( (unsigned short*) pseudogram , psize);
	
	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &amp;one;
	
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) &lt; 0)
	{
		perror(&quot;Error setting IP_HDRINCL&quot;);
		exit(0);
	}
	
	//loop if you want to flood :)
	while (1)
	{
		//Send the packet
		if (sendto (s, datagram, iph-&gt;tot_len ,	0, (struct sockaddr *) &amp;sin, sizeof (sin)) &lt; 0)
		{
			perror(&quot;sendto failed&quot;);
		}
		//Data send successfully
		else
		{
			printf (&quot;Packet Send. Length : %d \n&quot; , iph-&gt;tot_len);
		}
	}
	
	return 0;
}

//Complete
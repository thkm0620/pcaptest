#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
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
    printf("\n");
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    
    printf("Ethernet src mac : ");
    for(int i=6; i<12; i++) printf("%02X ",packet[i]);
    printf("\nEthernet dst mac : ");
    for(int i=0; i<6; i++) printf("%02X ",packet[i]);
    if((int)packet[12]*16*16+(int)packet[13]!=8*16*16){ // 0x0800
	printf("\n NOT IP\n");
	continue;
    }
    printf("\n IP src : ");
    for(int i=26; i<30; i++) printf("%d.",(int)packet[i]);
    printf("\n IP dst : ");
    for(int i=30; i<34; i++) printf("%d.",(int)packet[i]);
    if((int)packet[23]!=6){  // 0x06
	printf("\n NOT TCP\n");
	continue;
    }
    int iphLen=((int)packet[14]%16)*4; 
    printf("\n TCP src Port : %d",packet[14+iphLen]*16*16+packet[15+iphLen]);
    printf("\n TCP dst Port : %d",packet[16+iphLen]*16*16+packet[17+iphLen]);
    int tcphLen=((int)packet[iphLen+26]>>4)*4;
    int dataLen=header->caplen-(14+iphLen+tcphLen);
    if(dataLen<=0){
	printf("\n NO DATA \n");
	continue;
    }
    if(dataLen>32) dataLen=32;  //  print maximum 32bytes
    printf("\nDATA : ");
    for(int i=0; i<dataLen; i++) printf("%02X ",packet[14+iphLen+tcphLen+i]);
    printf("\n");

  }


  pcap_close(handle);
  return 0;

}

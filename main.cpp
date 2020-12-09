#include <pcap.h>

#include <iostream>
#include <map>

#include "airodump.h"

using namespace std;

typedef struct {
  int cnt;
  string ssid;
} BeaconInfo;

map<string, BeaconInfo> mp;

void usage() {
  printf("syntax : airodump <interface>\n");
  printf("sample : airodump mon0\n");
  return;
}

void printOutput() {
  system("clear");
  printf("BSSID              Beacons  ESSID\n\n");
  for (auto beacon : mp) {
    printf("%s  ", string(beacon.first).c_str());
    printf("%7d  ", beacon.second.cnt);
    printf("%s\n", beacon.second.ssid.c_str());
  }
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
  int res;

  //? Get handle
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);  // reponse time 1000 -> 1
  if (handle == nullptr) {
    fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
    return -1;
  }

  struct pcap_pkthdr* header;
  const u_char* packet;
  ieee80211_radiotap_header* radiotapHdr;
  ieee80211_beacon_mac_header* macHdr;
  uint8_t* framePtr;
  tagged_pararmeter* taggedParam;

  string bssid;
  string ssid;
  // uint32_t cur_packet_len;

  while (1) {
    res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;        // 패킷을 얻지 못함
    if (res == -1 || res == -2) {  // 패킷을 더이상 얻지 못하는 상태
      printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
      break;
    }

    // cur_packet_len = ntohl(header->caplen);

    //? parse radiotap header
    radiotapHdr = (ieee80211_radiotap_header*)(packet);
    packet += radiotapHdr->it_len;  //! why host?
    // cur_packet_len -= (uint32_t)ntohs(radiotapHdr->it_len);

    //? parse beacon mac header
    macHdr = (ieee80211_beacon_mac_header*)(packet);
    if (macHdr->type_subtype != macHdr->BEACON) continue;  //? is not beacon frame?
    bssid = string(macHdr->bssid);
    macHdr++;
    // cur_packet_len -= (uint32_t)sizeof(ieee80211_beacon_mac_header);

    //? parse beacon frame
    framePtr = reinterpret_cast<uint8_t*>(macHdr);

    //? skip fixed parameters
    framePtr += sizeof(fixed_pararmeter);
    // cur_packet_len -= (uint32_t)sizeof(fixed_pararmeter);

    //? parse tagged parameters for SSID
    /* for not ordered tagged params
    while (cur_packet_len > 0) {
      taggedParam = reinterpret_cast<tagged_pararmeter*>(framePtr);
      framePtr += 2;
      cur_packet_len -= 2;
      if (taggedParam->tag_num == taggedParam->SSID) {  //? is SSID parameter set?
        ssid.clear();
        for (uint8_t i = 0; i < taggedParam->tag_len; i++) ssid.push_back(*(framePtr++));
        break;
      }
      framePtr += taggedParam->tag_num;
      cur_packet_len -= uint32_t(taggedParam->tag_num);
    }
    */
    //* tagged parameter is ordered
    taggedParam = reinterpret_cast<tagged_pararmeter*>(framePtr);
    framePtr += 2;
    if (taggedParam->tag_num != taggedParam->SSID) continue;  //? is not SSID parameter set?
    ssid.clear();
    for (uint8_t i = 0; i < taggedParam->tag_len; i++) ssid.push_back(*(framePtr++));

    //? manage beacons
    if (mp.count(bssid)) {
      mp[bssid].cnt++;
    } else {
      mp.insert({bssid, {1, ssid}});
    }

    //? print output
    printOutput();
  }
  pcap_close(handle);
  return 0;
}
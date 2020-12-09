#pragma once

#include <cstdint>

#include "mac.h"

// radiotap_header https://www.radiotap.org/
#pragma pack(push, 1)
struct ieee80211_radiotap_header {
  uint8_t it_version; /* set to 0 */
  uint8_t it_pad;
  uint16_t it_len;     /* entire length */
  uint32_t it_present; /* fields present */
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ieee80211_beacon_mac_header {
  uint8_t type_subtype;  // 4: subtype, 2: type: 2: version
  uint8_t flags;
  uint16_t duration;           // microseconds
  Mac da;                      // destination_address
  Mac sa;                      // source_address
  Mac bssid;                   // bssid
  uint16_t fragment_sequence;  // 12: sequence number, 4: fragment number

  //type_subtype
  enum : uint8_t {
    BEACON = 0x80,
  };
};
#pragma pack(pop)

#pragma pack(push, 1)
struct fixed_pararmeter {
  uint64_t timestamp;
  uint16_t beacon_interval;
  uint16_t capa_info;  // capabilities_information
};
#pragma pack(pop)

#pragma pack(push, 1)
struct tagged_pararmeter {
  uint8_t tag_num;
  uint8_t tag_len;

  //tag_num
  enum : uint8_t {
    SSID = 0,  // SSID parameter set
  };
};
#pragma pack(pop)

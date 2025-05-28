#include "puf.h"

#include <WiFi.h>
#include <SHA3.h>

/*
extern "C" {
  #include "esp_system.h"
  #include "esp_wifi.h"
}
*/

extern "C" {
  #include "esp_mac.h"  // Per esp_read_mac() e ESP_MAC_WIFI_STA
}

String getPUF() {
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);

    SHA3_256 hasher;
    hasher.reset();
    hasher.update(mac, 6);

    uint8_t hash[32];
    hasher.finalize(hash, sizeof(hash));

    String result;
    char buf[3];
    for (int i = 0; i < 32; ++i) {
        sprintf(buf, "%02x", hash[i]);
        result += buf;
    }
    return result;
}
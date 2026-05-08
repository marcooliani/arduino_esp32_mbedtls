#include "puf.h"

extern "C" {
  #include "esp_mac.h"
  #include "mbedtls/sha3.h"
}

String getPUF() {
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);

    uint8_t hash[32];

    mbedtls_sha3(MBEDTLS_SHA3_256, mac, 6, hash, sizeof(hash));

    String result;
    char buf[3];
    for (int i = 0; i < 32; ++i) {
        sprintf(buf, "%02x", hash[i]);
        result += buf;
    }
    return result;
}

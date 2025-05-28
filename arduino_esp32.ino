#include <Preferences.h>
#include <mbedtls/base64.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>

#include "puf.h"

Preferences prefs; // Gestisce NVS

// IV fisso per praticità. In produzione, IV andrebbe randomizzato
uint8_t iv[16] = {0};

/*
  La cosa funziona più o meno come un dictionary in Python: 
  mynamespace è il nome del mio dictionary, ns_key la chiave
  (ce ne possono essere molteplici) a cui è poi associato il
  valore di segreto (dichiarato più in basso)
*/
void initNVS(const char* nvs_namespace, const char* nvs_key) {
  const char *segreto = "Questo è un esempio di segreto molto lungo che voglio cifrare e memorizzare!";

  // Create a NVS namespace called mynamespace
  prefs.begin(nvs_namespace, false);
  // Find for the key "ns_key" in NVS
  size_t storedSecret = prefs.getBytesLength(nvs_key);
  
  if (storedSecret == 0) {
    // Primo avvio: salvo il segreto in chiaro
    //const char *secret_char = segreto.c_str();
    size_t secret_size = strlen(segreto);

    // Memorizzo la stringa come array di byte in NVS
    prefs.putBytes(nvs_key, (uint8_t *)segreto, secret_size);

    //prefs.putString("ns_key", segreto); // Create the NVS key with the value
    Serial.println("Segreto inizializzato in NVS.");

  } else {
    Serial.println("Segreto già presente in NVS, nessuna scrittura effettuata.");
  
  }

  prefs.end();
}

/* 
 Creo un seed partendo dal valore ottenuto dalla PUF.
 seed[] dovrebbe essere 32 byte se si usa SHA256, 64 se
 si utilizza SHA512
 */
void createSeed(uint8_t *seed, const int seed_len) {
  String puf = getPUF();
  Serial.print("PUF: ");
  Serial.println(puf);

  const unsigned char *salt = (const unsigned char *)"salt";
  const int iterations = 2048;

  // mbedtls_pkcs5_pbkdf2_hmac() a quanto pare è deprecated...
  int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(
    MBEDTLS_MD_SHA256,
    (const unsigned char *)puf.c_str(), 
    puf.length(),
    salt, 
    sizeof(salt),
    iterations,
    seed_len,
    seed
  );

  Serial.print("Seed: ");
  for (int i = 0; i < seed_len; i++) {
    if (seed[i] < 16) 
      Serial.print('0'); // padding per valori < 0x10
    Serial.print(seed[i], HEX); // Questo, assieme alla riga precedente, equivale a
                                // printf("%02X", seed[i])
  }
  
  Serial.println();
}

void derive_aes_key_from_seed(const uint8_t *seed, size_t seed_len, uint8_t *aes_key_out) {
  mbedtls_sha256(seed, seed_len, aes_key_out, 0); // Simple SHA-256 hash
}

/*
 Setto la chiave AES per la cifratura dopo averla derivata
 */
void setEncryptionKey(esp_aes_context *ctx, uint8_t *aes_key, unsigned int keybit) {
  uint8_t seed[32];
  uint8_t derived_aes_key[32];
  createSeed(seed, sizeof(seed));
  derive_aes_key_from_seed(seed, sizeof(seed), derived_aes_key);

  mbedtls_aes_setkey_enc(ctx, derived_aes_key, keybit);

  Serial.print("AES Encryption Key: ");
  for (int i=0; i<32; i++) {
     if (derived_aes_key[i] < 16) 
      Serial.print('0');
    Serial.print(derived_aes_key[i], HEX);
  }
  Serial.println();
}

/*
 Setto la chiave AES per la decifratura dopo averla derivata.
 Mi sembra un'operazione abbastanza inutile dato che fa le stesse
 cose della funzione precedente, ma dato che era nella libreria...
 */
void setDecryptionKey(esp_aes_context *ctx, uint8_t *aes_key, unsigned int keybit) {
  uint8_t seed[32];
  uint8_t derived_aes_key[32];
  createSeed(seed, sizeof(seed));
  derive_aes_key_from_seed(seed, sizeof(seed), derived_aes_key);

  mbedtls_aes_setkey_dec(ctx, derived_aes_key, keybit);

  Serial.print("AES Decryption Key: ");
  for (int i=0; i<32; i++) {
     if (derived_aes_key[i] < 16) 
      Serial.print('0');
    Serial.print(derived_aes_key[i], HEX);
  }
  Serial.println();
}

/*
 Codifico il segreto criptato in base64, in modo da renderlo leggibile
 nella stampa a video (non sarebbe necessario, serve solo come 
 dimostrazione)
 */
void encodeBase64(const uint8_t* input, size_t input_len, String& out_b64) {
  size_t output_len = 0;
  size_t expected_len = ((input_len + 2) / 3) * 4 + 1;
  uint8_t output[expected_len];

  int ret = mbedtls_base64_encode(output, expected_len, &output_len, input, input_len);
  if (ret == 0) {
    output[output_len] = '\0';  // assicurati che sia una stringa
    out_b64 = (char*)output;
  } else {
    out_b64 = "";
    Serial.println("Errore nella codifica Base64.");
  }
}

/*
 Decofico il segreto memorizzato in base64
 */
void decodeBase64(const String& b64_input, uint8_t* output, size_t& output_len) {
  size_t input_len = b64_input.length();
  int ret = mbedtls_base64_decode(output, input_len, &output_len, (const uint8_t*)b64_input.c_str(), input_len);

  if (ret != 0) {
    Serial.println("Errore nella decodifica Base64.");
    output_len = 0;
  }
}

/*
 Cifro il segreto con AES dopo averlo recuperato da NVS
 */
void encryptSecret(const char *nvs_namespace, const char *nvs_key) {
  prefs.begin(nvs_namespace, false);
  size_t len = prefs.getBytesLength(nvs_key);

  if (len == 0) {
    Serial.println("Nessun segreto da cifrare.");
    prefs.end();
    return;
  }
 
  uint8_t buffer[len];
  prefs.getBytes(nvs_key, buffer, len);

  // Aggiusta dimensione per AES (multiplo di 16 byte)
  size_t padded_len = (len + 15) / 16 * 16;
  uint8_t plaintext[padded_len];
  memset(plaintext, 0, padded_len);
  memcpy(plaintext, buffer, len);

  uint8_t aes_key[32];
  mbedtls_aes_context ctx_aes;
  mbedtls_aes_init(&ctx_aes);

  setEncryptionKey(&ctx_aes, aes_key, 256);

  uint8_t encrypted[padded_len];
  uint8_t iv_copy[16];
  memcpy(iv_copy, iv, sizeof(iv));

  mbedtls_aes_crypt_cbc(&ctx_aes, MBEDTLS_AES_ENCRYPT, sizeof(plaintext), iv_copy, plaintext, encrypted);

  mbedtls_aes_free(&ctx_aes);

  // Salva "ENC:" + encrypted
  String header = "ENC:";

  String b64_encrypted; 
  encodeBase64(encrypted, padded_len, b64_encrypted);
  String to_store = header + b64_encrypted;
  Serial.println(to_store);
  prefs.putString(nvs_key, to_store);
  //prefs.putBytes(nvs_key, encrypted, sizeof(encrypted));

  Serial.println("Segreto cifrato e salvato.");
  
  prefs.end();
}

/*
 Decifro il segreto con AES dopo averlo recuperato da NVS e decodificato
 */
void decryptSecret(const char *nvs_namespace, const char *nvs_key) {
  prefs.begin(nvs_namespace, false);

  String stored = prefs.getString(nvs_key);
  if (stored.length() == 0) {
    Serial.println("Nessun segreto salvato.");
    prefs.end();
    return;
  }

  Serial.print("Segreto letto raw: ");
  Serial.println(stored);

  if (!stored.startsWith("ENC:")) {
    Serial.println("Il segreto non è cifrato.");
    prefs.end();
    return;
  }

  // Tolgo "ENC:" per ottenere il payload
  String b64_payload = stored.substring(4);
  Serial.print("Payload base64: ");
  Serial.println(b64_payload);

  uint8_t b64_decoded[128]; // Qui è meglio stare larghi
  size_t b64_decoded_len;
  decodeBase64(b64_payload, b64_decoded, b64_decoded_len);

  uint8_t decrypted[b64_decoded_len];
  
  uint8_t aes_key[32];
  esp_aes_context ctx_aes;
  esp_aes_init(&ctx_aes);

  setDecryptionKey(&ctx_aes, aes_key, 256);

  uint8_t iv_copy[16];
  memcpy(iv_copy, iv, sizeof(iv));

  mbedtls_aes_crypt_cbc(&ctx_aes, MBEDTLS_AES_DECRYPT, b64_decoded_len, iv_copy, b64_decoded, decrypted);
  mbedtls_aes_free(&ctx_aes);
  
  Serial.print("Segreto decriptato: ");
  Serial.println((char *)decrypted);
  
  prefs.end();
}

/*
 Stampo il valore del segreto (se) presente in NVS
 */
void printSecret(const char *nvs_namespace, const char *nvs_key) {
  prefs.begin(nvs_namespace, true);  // true = read-only

  String retrieved_secret = prefs.getString(nvs_key);
  
  if (retrieved_secret.length() > 0) {
    Serial.print("Segreto retrieved drom NVS: ");
    Serial.println(retrieved_secret);
  
  } else {
    size_t len = prefs.getBytesLength(nvs_key);
    if (len > 0) {
      uint8_t buffer[len];
      prefs.getBytes(nvs_key, buffer, len);

      Serial.print("Secret retrieved from NVS (Byte): ");
      String retrieved_secret = String((char*)buffer);
      Serial.println(retrieved_secret);
    } else {
      Serial.println("No secret found in NVS.");
    }
  }

  prefs.end();
}

/*
 Stampa il menu principale
 */
void printMenu() {
  Serial.println("\n--- Menu ---");
  Serial.println("1 - Initialize Secret in NVS");
  Serial.println("2 - Encrypt Secret");
  Serial.println("3 - Decrypt Secret");
  Serial.println("4 - Show NVS");
  Serial.println("Choose an option [1-4]: ");
}

void setup() {
  Serial.begin(115200);
  // This delay gives the chance to wait for a Serial Monitor without blocking if none is found
  //delay(1000);
  while (!Serial) {
    delay(10); // Attesa finché la connessione seriale è stabilita
  }
  printMenu();
}

void loop() {
  // put your main code here, to run repeatedly:
  if (Serial.available()) {
    char cmd = Serial.read();

    // Ignora \n e \r
    if (cmd == '\n' || cmd == '\r') 
      return;

    switch (cmd) {
      case '1':
        initNVS("mynamespace", "nvs_key");
        break;
      case '2':
        encryptSecret("mynamespace", "nvs_key");
        break;
      case '3':
        decryptSecret("mynamespace", "nvs_key");
        break;
      case '4':
        printSecret("mynamespace", "nvs_key");
        break;
    }
    printMenu();
  }
}

#include "../func.h"

int main (int argc, char *argv[]) {
  if (argc == 4) {



    unsigned int_password = str_hex(argv[1]);
    char *hash_type = argv[2];
    char *cipher_type = argv[3];
    char *text = TEXT;
    unsigned char *opentext;
    unsigned char *ciphertext;
    unsigned char password[PWRD_LEN];
    char filename[FILENAME_LEN];
    int ci_type = 0;



    if (!((strcmp(hash_type, "md5") == 0) || (strcmp(hash_type, "sha1") == 0))) {

      printf("Sorry, incorrect hash type.\n");
      return 0;

    } else if (!((strcmp(cipher_type, "3des") == 0) || (strcmp(cipher_type, "aes128") == 0) ||
                (strcmp(cipher_type, "aes192") == 0) || (strcmp(cipher_type, "aes256") == 0))) {

      printf("Sorry, incorrect cipher type.\n");
      return 0;

    }



    int IV_LEN[NUM_TYPES_CIPHERS] = {IV_LEN_3DES, IV_LEN_AES128, IV_LEN_AES192, IV_LEN_AES256}; // depend of cipher type
    int KEY_LEN[NUM_TYPES_CIPHERS] = {KEY_LEN_3DES, KEY_LEN_AES128, KEY_LEN_AES192, KEY_LEN_AES256};

    if (strcmp(cipher_type, "3des") == 0) {
      ci_type = DES3;
    } else if (strcmp(cipher_type, "aes128") == 0) {
      ci_type = AES128;
    } else if (strcmp(cipher_type, "aes192") == 0) {
      ci_type = AES192;
    } else {
      ci_type = AES256;
    }

    create_filename(hash_type, cipher_type, int_password, filename);

    int ot_len = strlen(text) + NULL_CHECK_LEN + 16 - (strlen(text) + NULL_CHECK_LEN) % IV_LEN[ci_type];

    opentext = (unsigned char *) malloc((ot_len) * sizeof(char));
    ciphertext = (unsigned char*) malloc((ot_len) * sizeof(char));


    memset(opentext, 0, ot_len);
    memcpy(opentext + NULL_CHECK_LEN, text, strlen(text));

    for (int i = 0; i < PWRD_LEN; i++) {
      password[PWRD_LEN - 1 - i] = int_password % LEN_CHAR;
      int_password /= LEN_CHAR;
    }

    unsigned char nonce[NONCE_LEN];
    unsigned char iv[IV_LEN[ci_type]];
    unsigned char iv_cpy[IV_LEN[ci_type]];
    unsigned char key[KEY_LEN[ci_type]];

    srand(time(NULL));

    generate(nonce, NONCE_LEN);
    generate(iv, IV_LEN[ci_type]);

    memcpy(iv_cpy, iv, IV_LEN[ci_type]);



    if (strcmp(hash_type, "md5") == 0) {

      unsigned char hmac[HMAC_MD5_LEN];
      hmac_md5(nonce, NONCE_LEN, password, PWRD_LEN, hmac);
      memcpy(key, hmac, HMAC_MD5_LEN);

      if (HMAC_MD5_LEN < KEY_LEN[ci_type]) {

        int delta = KEY_LEN[ci_type] - HMAC_MD5_LEN;
        unsigned char tmp_hmac[HMAC_MD5_LEN];
        hmac_md5(hmac, HMAC_MD5_LEN, password, PWRD_LEN, tmp_hmac);
        memcpy(key + HMAC_MD5_LEN, tmp_hmac, delta);

      }
    } else {

      unsigned char hmac[HMAC_SHA1_LEN];
      hmac_sha1(nonce, NONCE_LEN, password, PWRD_LEN, hmac);

      if (HMAC_SHA1_LEN > KEY_LEN[ci_type]) {
        memcpy(key, hmac, KEY_LEN[ci_type]);
      } else if (HMAC_SHA1_LEN < KEY_LEN[ci_type]) {

        memcpy(key, hmac, HMAC_SHA1_LEN);
        int delta = KEY_LEN[ci_type] - HMAC_SHA1_LEN;
        unsigned char tmp_hmac[HMAC_SHA1_LEN];
        hmac_sha1(hmac, HMAC_SHA1_LEN, password, PWRD_LEN, tmp_hmac);
        memcpy(key + HMAC_SHA1_LEN, tmp_hmac, delta);

      }
    }



    printf("File %s created.\n", filename);



    if (ci_type == 0) {
      des3_cbc_encrypt(opentext, ot_len, iv, key, ciphertext);
    } else {
      aes_cbc_encrypt(opentext, ot_len, iv, key, ciphertext, KEY_LEN[ci_type] * BYTE_LEN);
    }


    file_filling(filename, hash_type, ci_type, nonce, iv_cpy, ciphertext, IV_LEN[ci_type], ot_len);

    free(ciphertext);
    free(opentext);




  } else if (argc < 4) {
    printf("Sorry, not enough parameters.\n");
  } else {
    printf("Sorry, too many parameters.\n");
  }

  return 0;
}

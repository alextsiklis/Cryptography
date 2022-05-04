#include "func.h"

void help() {
  printf("ENCRYPT/DECRYPT application.\n");
  printf("Version: 1.0\n");
  printf("--------------------------------------\n");
  printf("For proper usage it needs at least 4 parameters:\n");
  printf(" -e (--enc) or -d (--dec) for encryption or decryption mode;\n");
  printf(" -p (--pass) with 4 bytes password (example: ffffffff);\n");
  printf(" -i (--input) with name of input file with data;\n");
  printf(" -o (--output) with name of output file (not necessary exist);\n");
  printf("All other parameters are optional and can be added only in encryption mode:\n");
  printf(" -h (--hmac) with hmac type (md5 or sha1), default - sha1;\n");
  printf(" -a (--alg) with algorythm type (3des, aes128, aes192, aes256), default - aes128;\n");
  printf(" -n (--nonce) with nonce data in HEX, default - generate randomly;\n");
  printf(" -v (--iv) with initial vector in HEX, default - generate randomly;\n");
  printf(" -s (--speed) (temporarily for nothing)\n\n");
}

unsigned wrong(struct check info) {
  if (info.en != 1)
    return 1;
  else if (info.password != 1)
    return 1;
  else if (info.input != 1)
    return 1;
  else if (info.output != 1)
    return 1;
  else if (info.hmac > 1)
    return 1;
  else if (info.alg > 1)
    return 1;
  else if (info.nonce > 1)
    return 1;
  else if (info.iv > 1)
    return 1;
  else if (info.speed > 1)
    return 1;
  return 0;
}

int checker(FILE *in) {
  char letter;
  int i;
  int flag = 0;
  int max_len[NUM_TYPES_CIPHERS] = {
    MAXLEN_3DES,
    MAXLEN_AES128,
    MAXLEN_AES192,
    MAXLEN_AES256};
  int min_len[NUM_TYPES_CIPHERS] = {
    MINLEN_3DES,
    MINLEN_AES128,
    MINLEN_AES192,
    MINLEN_AES256};
  int cipher_type;

  for (i = 0; fread(&letter, sizeof(char), 1, in) == 1; i++) {

    switch (i) {
      case 0:
        if (letter != 'E') {
          flag = 1;
        }
        break;
      case 1:
        if (letter != 'N') {
          flag = 1;
        }
        break;
      case 2:
        if (letter != 'C') {
          flag = 1;
        }
        break;
      case 3:
        if (!((letter == 0) || (letter == 1))) {
          flag = 1;
        }
        break;
      case 4:
        if (!((letter >= 0) && (letter <= 3))) {
          flag = 1;
        } else {
          cipher_type = letter;
        }
        break;
    }

    if (flag) {
      break;
    }
  }

  if ((i > max_len[cipher_type]) || (i < min_len[cipher_type])) {
    return 0;
  } else {
    return 1;
  }

}

unsigned str_hex(const char *str){
    const char *ptr;
    unsigned num;
    int num_of_simb;
    num_of_simb = 8;
    num = 0;

    for (ptr = str; *ptr; ptr++) {
        if (*ptr >= '0' && *ptr <= '9') {
            num = (num << 4) | (unsigned int)(*ptr - '0');
            num_of_simb--;
        }
        else if (*ptr >= 'A' && *ptr <= 'F') {
            num = (num << 4) | (unsigned int)(*ptr - 'A' + 10);
            num_of_simb--;
        }
        else if (*ptr >= 'a' && *ptr <= 'f') {
            num = (num << 4) | (unsigned int)(*ptr - 'a' + 10);
            num_of_simb--;
        }

    }

    num <<= (num_of_simb*4);

    return num;
}

char str_char(const char *str){
  const char *ptr;
  unsigned num;
  int num_of_simb;
  num_of_simb = 4;
  num = 0;

  for (ptr = str; *ptr; ptr++) {
      if (*ptr >= '0' && *ptr <= '9') {
          num = (num << 4) | (unsigned int)(*ptr - '0');
          num_of_simb--;
      }
      else if (*ptr >= 'A' && *ptr <= 'F') {
          num = (num << 4) | (unsigned int)(*ptr - 'A' + 10);
          num_of_simb--;
      }
      else if (*ptr >= 'a' && *ptr <= 'f') {
          num = (num << 4) | (unsigned int)(*ptr - 'a' + 10);
          num_of_simb--;
      }

  }

  num <<= (num_of_simb*4);

  return num;
}

void generate(unsigned char *string, int len) {
  for (int i = 0; i < len; i++)
    string[i] = (unsigned char) (rand() % LEN_CHAR);
}

void md5(unsigned char *data, size_t data_len, unsigned char *hash) {
  MD5_CTX ctx;
  MD5_Init(&ctx);
  MD5_Update(&ctx, data, data_len);
  MD5_Final(hash, &ctx);
}

void sha1(unsigned char *data, size_t data_len, unsigned char *hash) {
  SHA_CTX ctx;
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, data, data_len);
  SHA1_Final(hash, &ctx);
}

void des3_cbc_encrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out) {
  DES_cblock key1, key2, key3;
	DES_key_schedule ks1, ks2, ks3;

	memcpy(key1, key, 8);
	memcpy(key2, key + 8, 8);
	memcpy(key3, key + 16, 8);

	DES_set_key((DES_cblock *) key1, &ks1);
	DES_set_key((DES_cblock *) key2, &ks2);
	DES_set_key((DES_cblock *) key3, &ks3);

	DES_ede3_cbc_encrypt(in, out, in_len, &ks1, &ks2, &ks3, (DES_cblock *) iv, DES_ENCRYPT);
}

void aes_cbc_encrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out, unsigned key_len) {
  AES_KEY akey;
	AES_set_encrypt_key(key, key_len, &akey);
	AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_ENCRYPT);
}

void des3_cbc_decrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out) {
  DES_cblock key1, key2, key3;
	DES_key_schedule ks1, ks2, ks3;

	memcpy(key1, key, 8);
	memcpy(key2, key + 8, 8);
	memcpy(key3, key + 16, 8);

	DES_set_key((DES_cblock *) key1, &ks1);
	DES_set_key((DES_cblock *) key2, &ks2);
	DES_set_key((DES_cblock *) key3, &ks3);

	DES_ede3_cbc_encrypt(in, out, in_len, &ks1, &ks2, &ks3, (DES_cblock *) iv, DES_DECRYPT);
}

void aes_cbc_decrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out, unsigned key_len) {
  AES_KEY akey;
	AES_set_decrypt_key(key, key_len, &akey);
	AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_DECRYPT);
}

void hmac_md5(unsigned char *text, size_t text_len, unsigned char *key, size_t key_len, unsigned char *md) {
  MD5_CTX context;
  unsigned char ipad[PADS_LEN];
  unsigned char opad[PADS_LEN];

  memset(ipad, 0x36, PADS_LEN);
  memset(opad, 0x5c, PADS_LEN);

  for (unsigned i = 0; i < key_len; i++) {
    ipad[i] ^= key[i];
    opad[i] ^= key[i];
  }

  MD5_Init(&context);
  MD5_Update(&context, ipad, (PADS_LEN-1));
  MD5_Update(&context, text, text_len);
  MD5_Final(md, &context);

  MD5_Init(&context);
  MD5_Update(&context, opad, (PADS_LEN-1));
  MD5_Update(&context, md, HMAC_MD5_LEN);
  MD5_Final(md, &context);
}

void hmac_sha1(unsigned char *text, size_t text_len, unsigned char *key, size_t key_len, unsigned char *md) {
  SHA_CTX context;
  unsigned char ipad[PADS_LEN];
  unsigned char opad[PADS_LEN];

  memset(ipad, 0x36, PADS_LEN);
  memset(opad, 0x5c, PADS_LEN);

  for (unsigned i = 0; i < key_len; i++) {
    ipad[i] ^= key[i];
    opad[i] ^= key[i];
  }

  SHA1_Init(&context);
  SHA1_Update(&context, ipad, (PADS_LEN-1));
  SHA1_Update(&context, text, text_len);
  SHA1_Final(md, &context);

  SHA1_Init(&context);
  SHA1_Update(&context, opad, (PADS_LEN-1));
  SHA1_Update(&context, md, HMAC_SHA1_LEN);
  SHA1_Final(md, &context);
}

void readinfo(FILE *in, int *hash_type, int *ci_type, unsigned char *nonce, unsigned char *iv, unsigned char *ciphertext, int *ct_len) {

  int IV_LEN[NUM_TYPES_CIPHERS] = {IV_LEN_3DES, IV_LEN_AES128, IV_LEN_AES192, IV_LEN_AES256};

  char letter;

  fread(&letter, sizeof(unsigned char), 1, in);
  fread(&letter, sizeof(unsigned char), 1, in);
  fread(&letter, sizeof(unsigned char), 1, in);

  fread(hash_type, sizeof(unsigned char), 1, in);

  fread(ci_type, sizeof(unsigned char), 1, in);

  fread(nonce, sizeof(unsigned char), NONCE_LEN, in);

  fread(iv, sizeof(unsigned char), IV_LEN[*ci_type], in);

  for((*ct_len) = 0; fread(&letter, sizeof(char), 1, in) == 1; (*ct_len)++)
    ciphertext[(*ct_len)] = (unsigned char) letter;

}

void file_filling(char *filename, int hash_type, int ci_type, unsigned char *nonce, unsigned char *iv, unsigned char *text, int iv_len, int text_len) {
  FILE * output;
  output = fopen(filename, "wb");

  fprintf(output, "ENC%c", hash_type);

  fprintf(output, "%c", ci_type);

  for(int i = 0; i < NONCE_LEN; i++) {
    fprintf(output, "%c", nonce[i]);
  }

  for(int i = 0; i < iv_len; i++) {
    fprintf(output, "%c", iv[i]);
  }

  for(int i = 0; i < text_len; i++) {
    fprintf(output, "%c", text[i]);
  }

  fclose(output);
}

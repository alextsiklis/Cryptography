#include "func.h"

int main (int argc, char *argv[]) {

  unsigned enc = 2;

  unsigned int_pass;
  char in_filename[30];
  char out_filename[30];
  int hmac_type = 1;
  int alg_type = 1;
  char tmp_nonce[NONCE_LEN*2];
  char tmp_iv[MAX_IV_LEN*2];

  struct check info;
  info.en = 0;
  info.input = 0;
  info.output = 0;
  info.password = 0;
  info.hmac = 0;
  info.alg = 0;
  info.nonce = 0;
  info.iv = 0;
  info.speed = 0;


  opterr = 0;

	const char *short_options = "edp:i:o:h:a:n:v:";
	const struct option long_options[] = {
		{"enc", no_argument, NULL, 'e'},
		{"dec", no_argument, NULL, 'd'},
		{"pass", required_argument, NULL, 'p'},
		{"input", required_argument, NULL, 'i'},
    {"output", required_argument, NULL, 'o'},
    {"hmac", required_argument, NULL, 'h'},
    {"alg", required_argument, NULL, 'a'},
    {"nonce", required_argument, NULL, 'n'},
    {"iv", required_argument, NULL, 'v'},
    {"speed", no_argument, NULL, 's'},
		{NULL, 0, NULL, 0}
	};

	int rez;
	int option_index;

	while ((rez = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1){

		switch (rez){
			case 'e':
        enc = 1;
        info.en++;
        break;
      case 'd':
        enc = 0;
        info.en++;
        break;
      case 'p':
        int_pass = str_hex(optarg);
        info.password++;
        break;
      case 'i':
        memcpy(in_filename, optarg, strlen(optarg));
        info.input++;
        break;
      case 'o':
        memcpy(out_filename, optarg, strlen(optarg));
        info.output++;
        break;
      case 'h':
        if (!(strcmp(optarg, "md5")))
          hmac_type = 0;
        else if (!(strcmp(optarg, "sha1")))
          hmac_type  = 1;
        else {
          printf("Sorry, incorrect hash type.\n");
          help();
          return 0;
        }
        info.hmac++;
        break;
      case 'a':
        if (!(strcmp(optarg, "3des")))
          alg_type = 0;
        else if (!(strcmp(optarg, "aes128")))
          alg_type  = 1;
        else if (!(strcmp(optarg, "aes192")))
          alg_type  = 2;
        else if (!(strcmp(optarg, "aes256")))
          alg_type  = 3;
        else {
          printf("Sorry, incorrect algorythm type.\n");
          help();
          return 0;
        }
        info.alg++;
        break;
      case 'n':
        memcpy(tmp_nonce, optarg, strlen(optarg));
        info.nonce++;
        break;
      case 'v':
        memcpy(tmp_iv, optarg, strlen(optarg));
        info.iv++;
        break;
      case 's':
        info.speed++;
        break;
			case '?': default: {
        printf("Please, check parameters.\n\n");
        help();
        return 0;
				break;
			};
		};
	};


  if (wrong(info)) {
    printf("Please, check parameters.\n\n");
    help();
    return 0;
  } else if (enc == 0 && (info.hmac + info.alg + info.nonce + info.iv) != 0) {
    printf("Too many parameters for decoding.\n\n");
    help();
    return 0;
  }



  int IV_LEN[NUM_TYPES_CIPHERS] = {IV_LEN_3DES, IV_LEN_AES128, IV_LEN_AES192, IV_LEN_AES256}; // depend of cipher type
  int KEY_LEN[NUM_TYPES_CIPHERS] = {KEY_LEN_3DES, KEY_LEN_AES128, KEY_LEN_AES192, KEY_LEN_AES256};

  FILE *in;

  if ((in = fopen(in_filename, "rb")) == NULL) {
		printf("Please, enter correct filename\n");
    return 0;
  }



  unsigned char password[PWRD_LEN];
  unsigned char nonce[NONCE_LEN];
  unsigned char iv[MAX_IV_LEN];
  unsigned char iv_cpy[MAX_IV_LEN];
  unsigned char ciphertext[MAX_TEXT_LEN];
  unsigned char opentext[MAX_TEXT_LEN];
  int ct_len = 0;


  for (int i = 0; i < PWRD_LEN; i++) {
    password[PWRD_LEN - 1 - i] = int_pass % LEN_CHAR;
    int_pass /= LEN_CHAR;
  }


  if (enc == 0) {
    int pass;
    pass = checker(in);

    fclose(in);

    if (!(pass)) {
      printf("Incorrect file to decoding.\n\n");
      help();
      return 0;
    }

    in = fopen(in_filename, "rb");

    readinfo(in, &hmac_type, &alg_type, nonce, iv, ciphertext, &ct_len);

    fclose(in);
  } else {
    char letter;

    memset(opentext, 0, NULL_CHECK_LEN);
    ct_len += NULL_CHECK_LEN;

    for(; fread(&letter, sizeof(char), 1, in) == 1; ct_len++)
      opentext[ct_len] = (unsigned char) letter;

    unsigned delta = 16 - ct_len % IV_LEN[alg_type];
    memset((opentext + ct_len), ' ', delta);
    ct_len += delta;
    char tmp[2];
    srand(time(NULL));
    if (info.nonce == 0)
      generate(nonce, NONCE_LEN);
    else {
      for (int i = 0; i < NONCE_LEN; i++) {
        tmp[0] = tmp_nonce[2*i];
        tmp[1] = tmp_nonce[2*i+1];
        nonce[i] = str_char(tmp);
      }
    }

    if (info.iv == 0)
      generate(iv, IV_LEN[alg_type]);
    else {
      for (int i = 0; i < IV_LEN[alg_type]; i++) {
        tmp[0] = tmp_iv[2*i];
        tmp[1] = tmp_iv[2*i+1];
        iv[i] = str_char(tmp);
      }
    }

  }

  memcpy(iv_cpy, iv, IV_LEN[alg_type]);

  unsigned char key[KEY_LEN[alg_type]];

  if (hmac_type == 0) {

    unsigned char hmac[HMAC_MD5_LEN];
    hmac_md5(nonce, NONCE_LEN, password, PWRD_LEN, hmac);
    memcpy(key, hmac, HMAC_MD5_LEN);

    if (HMAC_MD5_LEN < KEY_LEN[alg_type]) {

      int delta = KEY_LEN[alg_type] - HMAC_MD5_LEN;
      unsigned char tmp_hmac[HMAC_MD5_LEN];
      hmac_md5(hmac, HMAC_MD5_LEN, password, PWRD_LEN, tmp_hmac);
      memcpy(key + HMAC_MD5_LEN, tmp_hmac, delta);

    }
  } else {

    unsigned char hmac[HMAC_SHA1_LEN];
    hmac_sha1(nonce, NONCE_LEN, password, PWRD_LEN, hmac);

    if (HMAC_SHA1_LEN > KEY_LEN[alg_type]) {
      memcpy(key, hmac, KEY_LEN[alg_type]);
    } else if (HMAC_SHA1_LEN < KEY_LEN[alg_type]) {

      memcpy(key, hmac, HMAC_SHA1_LEN);
      int delta = KEY_LEN[alg_type] - HMAC_SHA1_LEN;
      unsigned char tmp_hmac[HMAC_SHA1_LEN];
      hmac_sha1(hmac, HMAC_SHA1_LEN, password, PWRD_LEN, tmp_hmac);
      memcpy(key + HMAC_SHA1_LEN, tmp_hmac, delta);

    }
  }


  if (enc) {
    if (alg_type == 0) {
      des3_cbc_encrypt(opentext, ct_len, iv, key, ciphertext);
    } else {
      aes_cbc_encrypt(opentext, ct_len, iv, key, ciphertext, KEY_LEN[alg_type] * BYTE_LEN);
    }

    file_filling(out_filename, hmac_type, alg_type, nonce, iv_cpy, ciphertext, IV_LEN[alg_type], ct_len);
  } else {
    if (alg_type == 0) {
      des3_cbc_decrypt(ciphertext, ct_len, iv, key, opentext);
    } else {
      aes_cbc_decrypt(ciphertext, ct_len, iv, key, opentext, KEY_LEN[alg_type] * BYTE_LEN);
    }

    for (int j = 0; j < NULL_CHECK_LEN; j++) {
      if (opentext[j] != 0){
        printf("Incorrect password, please, try again.\n");
        return 0;
      }
    }

    FILE *out;
    out = fopen(out_filename, "wb");

    for(int i = NULL_CHECK_LEN; i < ct_len; i++) {
      fprintf(out, "%c", opentext[i]);
    }

    fclose(out);
  }


}

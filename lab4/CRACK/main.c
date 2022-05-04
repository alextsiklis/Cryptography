#include "../func.h"

int main (int argc, char *argv[]) {

  int verbose = 0;
  int problem = 0;
  int speed = 0;

  opterr = 0;

	const char *short_options = "vsh";
	const struct option long_options[] = {
		{"verbose", no_argument, NULL, 'v'},
    {"speed", no_argument, NULL, 's'},
    {"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	int rez;
	int option_index;

	while ((rez = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1){

		switch (rez){
			case 'v': {
				verbose = 1;
				break;
			};
      case 's': {
				speed = 1;
				break;
			};
      case 'h': {
				help();
        return 0;
			};
			case '?': default: {
        problem = 1;
				printf("Found unknown option\n");
				break;
			};
		};
	};

  if (problem)
    return 0;

  char *filename = argv[argc-1];
  FILE *in;
  int pass = 0;

  if ((in = fopen(filename, "rb")) == NULL) {
		printf("Please, enter correct filename\n");
    return 0;
  }

  pass = checker(in);

  fclose(in);

  if (!(pass)) {
    printf("Invalid file.\n");
    return 0;
  }

  printf("Valid file!\n");

  int hash_type = 0;
  int ci_type = 0;
  int KEY_LEN[NUM_TYPES_CIPHERS] = {KEY_LEN_3DES, KEY_LEN_AES128, KEY_LEN_AES192, KEY_LEN_AES256};
  int IV_LEN[NUM_TYPES_CIPHERS] = {IV_LEN_3DES, IV_LEN_AES128, IV_LEN_AES192, IV_LEN_AES256};


  unsigned char nonce[NONCE_LEN];
  unsigned char iv[MAX_IV_LEN];
  unsigned char ciphertext[MAX_TEXT_LEN];
  int ct_len = 0;
  unsigned int_pwrd;

  in = fopen(filename, "rb");

  readinfo(in, &hash_type, &ci_type, nonce, iv, ciphertext, &ct_len);

  print_data(hash_type, ci_type, nonce, iv, ciphertext, ct_len);

  fclose(in);

  printf("\nStart cracking\n\n\n");

  unsigned char password[PWRD_LEN];
  unsigned char key[KEY_LEN[ci_type]];
  unsigned char opentext[ct_len];
  unsigned char iv_cpy[IV_LEN[ci_type]];
  unsigned char hmac[HMAC_MAX_LEN];
  unsigned char tmp_hmac[HMAC_MAX_LEN];
  int isright = 0;
  unsigned i = 0;
  int delta = 0;

  memcpy(iv_cpy, iv, IV_LEN[ci_type]);


  if (hash_type == 0) {
    delta = KEY_LEN[ci_type] - HMAC_MD5_LEN;
  } else {
    delta = KEY_LEN[ci_type] - HMAC_SHA1_LEN;
  }

  if (verbose) {
    printf("Current: 00000000 - 0000ffff\n");
  }


  struct tms tmsstart, tmsend;

  clock_t start;
  clock_t current;
  clock_t previous;

  pid_t pid;

  start = times(&tmsstart);
  current = times(&tmsend);

  double time_in_seconds = 0;

  if (speed) {
    pid = fork();

    if (pid == 0) {

      for (i = 0; i <= UINT_MAX; i += 2) {

        int_pwrd = i;
        isright = 1;

        memcpy(iv, iv_cpy, IV_LEN[ci_type]);
        memset(key, 0, KEY_LEN[ci_type]);
        memset(opentext, 0, ct_len);

        for (int j = 0; j < PWRD_LEN; j++) {
          password[PWRD_LEN - 1 - j] = (unsigned char) int_pwrd % LEN_CHAR;
          int_pwrd /= LEN_CHAR;
        }


        if ((!(i & 0xffff)) && (verbose) && (i != 0)) {

          previous = current;
          current = times(&tmsend);

          printf("Current: %08x - %08x | ", i, (i + 0xffff));

          time_in_seconds = (double) (current - previous) / CLOCKS_PER_SEC;
          printf("Current speed: %6.0f c/s | ", (0x10000 / time_in_seconds));

          time_in_seconds = (double) (current - start) / CLOCKS_PER_SEC;
          printf("Average speed: %6.0f c/s\n", (i / time_in_seconds));

        }




        if (hash_type == 0) {

          hmac_md5(nonce, NONCE_LEN, password, PWRD_LEN, hmac);
          memcpy(key, hmac, HMAC_MD5_LEN);

          if (HMAC_MD5_LEN < KEY_LEN[ci_type]) {

            hmac_md5(hmac, HMAC_MD5_LEN, password, PWRD_LEN, tmp_hmac);
            memcpy(key + HMAC_MD5_LEN, tmp_hmac, delta);

          }
        } else {

          hmac_sha1(nonce, NONCE_LEN, password, PWRD_LEN, hmac);

          if (HMAC_SHA1_LEN > KEY_LEN[ci_type]) {
            memcpy(key, hmac, KEY_LEN[ci_type]);
          } else if (HMAC_SHA1_LEN < KEY_LEN[ci_type]) {

            memcpy(key, hmac, HMAC_SHA1_LEN);
            hmac_sha1(hmac, HMAC_SHA1_LEN, password, PWRD_LEN, tmp_hmac);
            memcpy(key + HMAC_SHA1_LEN, tmp_hmac, delta);

          }
        }



        if (ci_type == 0) {
          des3_cbc_decrypt(ciphertext, ct_len, iv, key, opentext);
        } else {
          aes_cbc_decrypt(ciphertext, ct_len, iv, key, opentext, KEY_LEN[ci_type] * BYTE_LEN);
        }


        for (int j = 0; j < NULL_CHECK_LEN; j++) {
          if (opentext[j] != 0){
            isright = 0;
            break;
          }
        }

        if (i == UINT_MAX)
          break;

        if (isright)
          break;

      }


    } else if (!isright){

      for (i = 1; i <= UINT_MAX; i += 2) {

        int_pwrd = i;
        isright = 1;

        memcpy(iv, iv_cpy, IV_LEN[ci_type]);
        memset(key, 0, KEY_LEN[ci_type]);
        memset(opentext, 0, ct_len);

        for (int j = 0; j < PWRD_LEN; j++) {
          password[PWRD_LEN - 1 - j] = (unsigned char) int_pwrd % LEN_CHAR;
          int_pwrd /= LEN_CHAR;
        }


        if ((!(i & 0xffff)) && (verbose) && (i != 0)) {

          previous = current;
          current = times(&tmsend);

          printf("Current: %08x - %08x | ", i, (i + 0xffff));

          time_in_seconds = (double) (current - previous) / CLOCKS_PER_SEC;
          printf("Current speed: %6.0f c/s | ", (0x10000 / time_in_seconds));

          time_in_seconds = (double) (current - start) / CLOCKS_PER_SEC;
          printf("Average speed: %6.0f c/s\n", (i / time_in_seconds));

        }




        if (hash_type == 0) {

          hmac_md5(nonce, NONCE_LEN, password, PWRD_LEN, hmac);
          memcpy(key, hmac, HMAC_MD5_LEN);

          if (HMAC_MD5_LEN < KEY_LEN[ci_type]) {

            hmac_md5(hmac, HMAC_MD5_LEN, password, PWRD_LEN, tmp_hmac);
            memcpy(key + HMAC_MD5_LEN, tmp_hmac, delta);

          }
        } else {

          hmac_sha1(nonce, NONCE_LEN, password, PWRD_LEN, hmac);

          if (HMAC_SHA1_LEN > KEY_LEN[ci_type]) {
            memcpy(key, hmac, KEY_LEN[ci_type]);
          } else if (HMAC_SHA1_LEN < KEY_LEN[ci_type]) {

            memcpy(key, hmac, HMAC_SHA1_LEN);
            hmac_sha1(hmac, HMAC_SHA1_LEN, password, PWRD_LEN, tmp_hmac);
            memcpy(key + HMAC_SHA1_LEN, tmp_hmac, delta);

          }
        }



        if (ci_type == 0) {
          des3_cbc_decrypt(ciphertext, ct_len, iv, key, opentext);
        } else {
          aes_cbc_decrypt(ciphertext, ct_len, iv, key, opentext, KEY_LEN[ci_type] * BYTE_LEN);
        }


        for (int j = 0; j < NULL_CHECK_LEN; j++) {
          if (opentext[j] != 0){
            isright = 0;
            break;
          }
        }

        if (i == UINT_MAX)
          break;

        if (isright)
          break;

      }


    }

  }





  if (!speed) {
    for (; i <= UINT_MAX; i++) {

      int_pwrd = i;
      isright = 1;

      memcpy(iv, iv_cpy, IV_LEN[ci_type]);
      memset(key, 0, KEY_LEN[ci_type]);
      memset(opentext, 0, ct_len);

      for  (int j = 0; j < PWRD_LEN; j++) {
        password[PWRD_LEN - 1 - j] = (unsigned char) int_pwrd % LEN_CHAR;
        int_pwrd /= LEN_CHAR;
      }


      if ((!(i & 0xffff)) && (verbose) && (i != 0)) {

        previous = current;
        current = times(&tmsend);

        printf("Current: %08x - %08x | ", i, (i + 0xffff));

        time_in_seconds = (double) (current - previous) / CLOCKS_PER_SEC;
        printf("Current speed: %6.0f c/s | ", (0x10000 / time_in_seconds));

        time_in_seconds = (double) (current - start) / CLOCKS_PER_SEC;
        printf("Average speed: %6.0f c/s\n", (i / time_in_seconds));

      }




      if (hash_type == 0) {

        hmac_md5(nonce, NONCE_LEN, password, PWRD_LEN, hmac);
        memcpy(key, hmac, HMAC_MD5_LEN);

        if (HMAC_MD5_LEN < KEY_LEN[ci_type]) {

          hmac_md5(hmac, HMAC_MD5_LEN, password, PWRD_LEN, tmp_hmac);
          memcpy(key + HMAC_MD5_LEN, tmp_hmac, delta);

        }
      } else {

        hmac_sha1(nonce, NONCE_LEN, password, PWRD_LEN, hmac);

        if (HMAC_SHA1_LEN > KEY_LEN[ci_type]) {
          memcpy(key, hmac, KEY_LEN[ci_type]);
        } else if (HMAC_SHA1_LEN < KEY_LEN[ci_type]) {

          memcpy(key, hmac, HMAC_SHA1_LEN);
          hmac_sha1(hmac, HMAC_SHA1_LEN, password, PWRD_LEN, tmp_hmac);
          memcpy(key + HMAC_SHA1_LEN, tmp_hmac, delta);

        }
      }



      if (ci_type == 0) {
        des3_cbc_decrypt(ciphertext, ct_len, iv, key, opentext);
      } else {
        aes_cbc_decrypt(ciphertext, ct_len, iv, key, opentext, KEY_LEN[ci_type] * BYTE_LEN);
      }


      for (int j = 0; j < NULL_CHECK_LEN; j++) {
        if (opentext[j] != 0){
          isright = 0;
          break;
        }
      }

      if (i == UINT_MAX)
        break;

      if (isright)
        break;

    }
  }

  if (speed)
    waitpid(pid, NULL, 0);

  current = times(&tmsend);


  printf("Found: ");
  for (int j = 0; j < PWRD_LEN; j++) {
    printf("%02hhx", password[j]);
  }

  if (verbose) {
    time_in_seconds = (double) (current - start) / CLOCKS_PER_SEC;
    printf(" | Average speed: %6.0f c/s\n", (i / time_in_seconds));
  }


  printf("\nMessage's text is: \n\n");
  for (int j = NULL_CHECK_LEN; j < ct_len; j++) {
    printf("%c", opentext[j]);
  }

  printf("\n\n");

  printf("\nMessage's text in HEX is: \n\n");
  for (int j = NULL_CHECK_LEN; j < ct_len; j++) {
    printf("%02hhx", opentext[j]);
  }

  printf("\n\n");

  return 0;
}

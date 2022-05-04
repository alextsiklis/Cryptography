#include "func.h"

int main(int argc, char **argv) { 
	
	int need2Bdone = 1;
	
	char *in_filename = argv[argc-1];
	char * key_filename;
	
	opterr = 0;
    
	const char *short_options = "hvk:";
	const struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'v'},
		{"key", required_argument, NULL, 'k'},
		{NULL, 0, NULL, 0}
	};	
	
	int rez;
	int option_index;

	while ((rez=getopt_long(argc,argv,short_options,
		long_options,&option_index))!=-1){

		switch (rez){
			case 'h': {
				help();
				need2Bdone = 0;
				break;
			};
			case 'v': {
				double ver = VERSION;
				printf("Version number = %.1lf\n", ver);
				need2Bdone = 0;
				break;
			};
			case 'k': {
				key_filename = optarg;
				break;
			};
			case '?': default: {
				printf("Found unknown option\nPlease, use --help (or -h) to get documentation\n");
				break;
			};
		};
	};
	
	FILE *in;
    FILE *key0;
    
	if (!need2Bdone) 
    	return 0;
    
    else if ((in = fopen(in_filename, "r")) == NULL)
		printf("Please, enter correct filename with input data\n");
	else if ((key0 = fopen(key_filename, "r")) == NULL)
		printf("Please, enter correct filename with key\n");
	else {
		char keys[KEYFILE_LEN];
		char c;
		char c_0[3];
    	c_0[2] = '\0';
		
		char regist_1[REGISTER_1_LEN];
    	char regist_2[REGISTER_2_LEN];
    	char regist_3[REGISTER_3_LEN];

    	char out_1;
    	char out_2;
    	char out_3;
    	char taken;
    	
    	fgets(keys, KEYFILE_LEN, key0);
    	
    	if (strlen(keys) != KEYFILE_LEN - 1) {
        	printf("Incorrect key value.\n");
        	fclose(in);
        	fclose(key0);
        	return 0;
    	}
    	fclose(key0);
    	
    	charge_regists(regist_1, regist_2, regist_3, keys);

    	while(((c_0[0] = fgetc(in)) != EOF) && ((c_0[1] = fgetc(in)) != EOF)) {
    	
        	c = str_hex(c_0);
        	
        	out_1 = regist_1[0];
        	taken = (char)(regist_1[ONE] ^ regist_1[THREE] ^ regist_1[FIVE] ^ (char) 1);
        	reg_left(regist_1, REGISTER_1_LEN, taken);
        	
        	out_2 = regist_2[0];
        	taken = (char)(regist_2[THREE] ^ regist_2[FIVE] ^ regist_2[SEVEN] ^ (char) 1);
        	reg_left(regist_2, REGISTER_2_LEN, taken);
        	
        	out_3 = regist_3[0];
        	taken = (char)(regist_3[FIVE] ^ regist_3[SEVEN] ^ regist_3[NINE] ^ (char) 1);
        	reg_left(regist_3, REGISTER_3_LEN, taken);
        	
        	printf("%02hhx", (Gamma(out_1, out_2, out_3) ^ c));
    	}
    	
    	fclose(in);
    	printf("\n");
	}
	return 0;
}

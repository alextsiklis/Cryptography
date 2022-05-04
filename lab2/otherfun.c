#include "otherfun.h"

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

void generate_data(const char *filename) {
	FILE *file;
	srand (time(NULL));
	file = fopen(filename, "w");
	
	for (int i = 0; i < 100000; i++)
		fprintf(file, "%08x", (unsigned) (rand() % (0xffffffff)));
	
	fclose(file);
}

void help() {
	printf("\nThis is Encoder/Decoder. It use AES algorythm.\n");
	printf("To use it properly, please, make sure that your input file (Open text) is in HEX format.\n");
	printf("\n-----------------------\n");
	printf("This program require this parameters for work: \n");
	printf("1)'--mode' or '-m' with argument ECB (Electronic Codebook), OFB (Output FeedBack) or CBC (Cipher Block Chaining) \n(This need to know mode of encoding/decoding)\n");
	printf("2) '--enc' or '-e' to be in encoding mode\n");
	printf("3) '--dec' or '-d' to be in decoding mode\n");
	printf("Be carefully, you need to enter only one of the first two parameters.\n");
	printf("4) '--key' or '-k' to enter a key (Key 0)\n");
	printf("5) '--iv' or '-i' to enter a init vector (only if you choose CBC or OFB mode)\n");
	printf("After all parameters you should enter name of input file (don't be mistaken).\n");
	printf("\n-----------------------\n");
	printf("Additional func: \n");
	printf("6) '--debug' or '-g' to start in debug mode of this program\n");
	printf("7) '--version' or '-v' show the version of this program\n");
	printf("8) '--help' or '-h' show this message\n");
	printf("9) '--speedtest' or '-s' show the time of coding/decoding 100000 blocks of information on your computer\n");
	printf("NOTE: if you use speedtest mode, be carefull, because all information in your input file will be change.\n");
	printf("\n-----------------------\n");
	printf("Here example of using this program:\n");
	printf("./cipher --mode=ecb --enc --key=ffffffff input.txt\n");
	printf("./cipher --mode=cbc --dec --key=ffffffff --iv=00000000 input.txt\n");
	printf("\n-----------------------\n");
}



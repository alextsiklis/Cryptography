#include "func.h"

char str_hex(const char *str){
    const char *ptr;
    char num;
    int num_of_simb;
    num_of_simb = 2;
    num = 0;

    for (ptr = str; *ptr; ptr++) {
        if (*ptr >= '0' && *ptr <= '9') {
            num = (num << 4) | (*ptr - '0');
            num_of_simb--;
        }
        else if (*ptr >= 'A' && *ptr <= 'F') {
            num = (num << 4) | (*ptr - 'A' + 10);
            num_of_simb--;
        }
        else if (*ptr >= 'a' && *ptr <= 'f') {
            num = (num << 4) | (*ptr - 'a' + 10);
            num_of_simb--;
        }
    }

    num <<= (num_of_simb * 4);

    return num;
}

void help() {
	printf("\nThis is Stream Encoder/Decoder.\n");
	printf("To use it properly, please, make sure that your input file (Open text) is in HEX format.\n");
	printf("\n-----------------------\n");
	printf("This program require this parameter for work: \n");
	printf("1) '--key' or '-k' to enter name of file with your key\n");
	printf("After parameter you should enter name of input file (don't be mistaken).\n");
	printf("\n-----------------------\n");
	printf("Additional func: \n");
	printf("2) '--version' or '-v' show the version of this program\n");
	printf("3) '--help' or '-h' show this message\n");
	printf("\n-----------------------\n");
	printf("Here example of using this program:\n");
	printf("./cipher --key=key.txt input.txt\n");
	printf("\n-----------------------\n");
}

void charge_regists(char *regist_1, char *regist_2, char *regist_3, const char *values) {
    char tmp[2];
    for (int i = 0; i < KEYFILE_LEN-1; i += 2) {
        tmp[0] = values[i];
        tmp[1] = values[i+1];

        if (i/2 < REGISTER_1_LEN)
            regist_1[i/2] = str_hex(tmp);
        else if ((i/2 - REGISTER_1_LEN) < REGISTER_2_LEN)
            regist_2[i/2 - REGISTER_1_LEN] = str_hex(tmp);
        else if ((i/2 - REGISTER_1_LEN - REGISTER_2_LEN) < REGISTER_3_LEN)
            regist_3[i/2 - REGISTER_1_LEN - REGISTER_2_LEN] = str_hex(tmp);
    }
}

void reg_left(char *regist, int reg_len, char last) {
    for(int i = 0; i < (reg_len - 1); i++) {
        regist[i] = regist[i + 1];
    }
    regist[reg_len - 1] = last;
}

char Gamma(char a, char b, char c) {
    return (char)(a*b*c + a*b + a*c + 1);
}

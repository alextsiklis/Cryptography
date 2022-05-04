#include <stdio.h>
#include <getopt.h>
#include <string.h>

#define REGISTER_1_LEN   7
#define REGISTER_2_LEN   9
#define REGISTER_3_LEN  11
#define KEYFILE_LEN     55
#define ONE              0
#define THREE            2
#define FIVE             4
#define SEVEN            6
#define NINE             8
#define VERSION        0.1

char str_hex(const char *str);

void help();

void charge_regists(char *regist_1, char *regist_2, char *regist_3, const char *values);

void reg_left(char *regist, int reg_len, char last);

char Gamma(char a, char b, char c);

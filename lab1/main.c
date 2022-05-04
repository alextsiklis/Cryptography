#include <stdio.h>
#include <string.h>

#define CHARNUM 64
#define BADCHAR "!#$%&'+-/=?^_`{|}~(),:;<>[\\]"

void add (unsigned long long *mask, unsigned int i);

void checkmask (const char mail[], unsigned long long *mask);

int checker (const char mail[], int i);

int main (int argc, char *argv[]) {
    FILE *in;
    in = fopen(argv[1], "r");
    char mail[CHARNUM];
    unsigned long long mask;
    while (fgets(mail, CHARNUM, in) != NULL) {
        mask = 0;
        checkmask(mail, &mask);
        printf("%llx\n", mask/2);
    }
    fclose(in);
    return 0;
}

void add (unsigned long long *mask, unsigned int i) {
    unsigned long long tmp = 1;
    tmp <<= i;
    *mask |= tmp;
}

int checker(const char mail[], int i) {
    int count1 = 0;
    int count2 = 0;
    int p1 = i;
    int p2 = i;
    while (strchr(BADCHAR, mail[i]) == NULL) {
        if (count1 == 1 && count2 == 1 && (mail[i] == '@' || mail[i] == '.')) {
            return i;
        }
        if (mail[i] == '@') {
            p2 = p1;
            p1 = i;
            count1++;
        }
        else if (mail[i] == '.') {
            p2 = p1;
            p1 = i;
            count2++;
        }
        i++;
        if (count1 > 1 || count2 > 1) {
            return -p2;
        }
    }
    if (count1 == 1 && count2 == 1) {
        return i;
    }
    return -i;
}

void checkmask (const char mail[], unsigned long long *mask) {
    int i = 0;
    int j = 0;
    unsigned int len;
    len = strlen(mail);
    while (i < (len-1)) {
        i = checker(mail, i);
        if (i == -(len-1)) {
            break;
        }
        else if (i > 0) {
            for (; j < i; j++) {
                add(mask, (len - j - 1));
            }
        }
        else {
            i = -i+1;
            j = i;
        }
    }
    printf("%x_", len);
}


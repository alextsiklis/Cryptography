#include <stdio.h>
#include <stdlib.h>

#define CHARNUM 64
#define ALLNUM 62

void search (char *mask, int len, int id);

int numofchar(char *str);

void multimask (int *index, char **password, int count, int ind);

int main (int argc, char *argv[]) {
    FILE *in;
    in = fopen(argv[1], "r");
    unsigned long long mask;
    char *password;
    password = malloc(CHARNUM * sizeof(char));
    int len = 0;
    int i;
    int count;

    while (!feof(in)) {
        fscanf(in, "%x_%llx", &len, &mask);

        for (int j = 0; j < CHARNUM; j++)
            password[j] = '0';
        password[len - 1] = '\n';
        password[len] = '\0';
        i = 0;
        count = 0;

        while (mask) {
            if (mask & 1) {
                password[len - 2 - i] = '1';
                if (i == 0 || password[len - 2 - i + 1] == '0')
                    count++;
            }
            i++;
            mask >>= 1;
        }

        int index[2 * count];
        index[2 * count - 1] = len - 1;
        int k = 0;
        for (int j = 0; j < len; j++) {
            if (password[j] == '1' && (j == 0 || password[j - 1] == '0')) {
                index[k] = j;
                k++;
            }
            else if (password[j] == '0' && (j == len || password[j - 1] == '1') && k % 2 == 1)  {
                index[k] = j;
                k++;
            }
        }

        multimask(index, &password, count, 0);
    }
    free(password);
    return 0;
}

void search (char *mask, int len, int id) {
    if (id == len - 1) {
        printf("%s", mask);
        return;
    }
    else if (mask[id] == '@' || mask[id] == '.' || mask[id] == '0')
        search(mask, len, id + 1);
    else {
        for (int i = 1; i < ALLNUM; i++) {
            if (i < 10)
                mask[id] = i + '0';
            else if (i < 36)
                mask[id] = i % 26 + 'A';
            else
                mask[id] = i % 26 + 'a';
            search(mask, len, id + 1);
        }
    }
}

int numofchar (char *str) {
    char *p;
    int num = 0;
    p = str;
    for (; *p != '\0'; p++){
        if (*p == '@' || *p == '.')
            num++;
    }
    return num;
}

void multimask (int *index, char **password , int count, int ind) {
    for (int j = index[ind] + 1; j < index[ind + 1] - 3; j++) {
        if ((*password)[j] != '0' && (*password)[j - 1] != '0' && (*password)[j + 1] != '0') {
            (*password)[j] = '@';
            for (int k = j + 2; k < index[ind + 1] - 1; k++) {
                if ((*password)[k] != '0' && (*password)[k + 1] != '0') {
                    (*password)[k] = '.';
                    if (ind < count - 1)
                        multimask(index, password, count, (ind + 2));
                    if (numofchar(*password) == count * 2)
                        search((*password), index[count * 2 - 1], index[ind]);
                    (*password)[k] = '1';
                }
            }
            (*password)[j] = '1';
        }
    }
}

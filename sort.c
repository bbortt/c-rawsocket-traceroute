/**
 * Licensed under the terms of the Apache 2.0 License.
 * Visit: https://www.apache.org/licenses/LICENSE-2.0.html.
 *
 * @author Timon Borter
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int cmp(const void *a, const void *b) {
    return strcmp(*(const char **) a, *(const char **) b);
}

int rcmp(const void *a, const void *b) {
    return cmp(b, a);
}

int main(int argc, char **argv) {
    int reverse = argc > 1 ? 0 == strcmp(argv[1], "-r") : 0;

    char **words = malloc(0);
    size_t words_size = 0;

    char buff[UINT16_MAX];
    char *word;

    uint16_t cnt = 0x00;
    while (fgets(buff, UINT16_MAX, stdin) != NULL) {
        buff[strcspn(buff, "\n")] = 0;
        size_t buff_size = strlen(buff) * sizeof(char *);
        word = malloc(buff_size);
        memcpy(word, buff, buff_size);
        words_size += buff_size;
        words = realloc(words, words_size);
        words[cnt++] = word;
    }

    if (0 == reverse) {
        qsort(words, cnt, sizeof(char *), cmp);
    } else {
        qsort(words, cnt, sizeof(char *), rcmp);
    }

    for (uint16_t i = 0x00; i < cnt; i++) {
        printf("words[%d]: %s\n", i, words[i]);
    }

    while (cnt--) {
        free(words[cnt]);
    }

    free(words);
}

#include <stdio.h>
#include <string.h>
#include "../mimedefang.h"

#define NUM_TESTS 5

static int test_num = 0;

static void
check(const char *label, const char *input,
      const char *expected_output, int expected_suspicious)
{
    dynamic_buffer dbuf;
    char input_copy[256];
    int suspicious, ok;

    dbuf_init(&dbuf);
    strncpy(input_copy, input, sizeof(input_copy) - 1);
    input_copy[sizeof(input_copy) - 1] = '\0';

    suspicious = safe_append_header(&dbuf, input_copy);

    ok = (DBUF_LEN(&dbuf) == (int)strlen(expected_output) &&
          memcmp(DBUF_VAL(&dbuf), expected_output, DBUF_LEN(&dbuf)) == 0 &&
          suspicious == expected_suspicious);

    test_num++;
    if (ok) {
        printf("ok %d - %s\n", test_num, label);
    } else {
        printf("not ok %d - %s\n", test_num, label);
        if (DBUF_LEN(&dbuf) != (int)strlen(expected_output) ||
            memcmp(DBUF_VAL(&dbuf), expected_output, DBUF_LEN(&dbuf)) != 0)
            printf("# expected %d bytes, got %d\n",
                   (int)strlen(expected_output), DBUF_LEN(&dbuf));
        if (suspicious != expected_suspicious)
            printf("# expected suspicious=%d, got %d\n",
                   expected_suspicious, suspicious);
    }

    dbuf_free(&dbuf);
}

int
main(void)
{
    printf("1..%d\n", NUM_TESTS);

    check("plain text unchanged",
          "hello world", "hello world", 0);

    check("CRLF at fold point: CR stripped",
          "Sunny\r\n holiday", "Sunny\n holiday", 0);

    check("bare CR replaced with space",
          "foo\rbar", "foo bar", 1);

    check("trailing CR replaced with space",
          "foo\r", "foo ", 1);

    check("multiple CRLF fold points",
          "a\r\nb\r\nc", "a\nb\nc", 0);

    return 0;
}

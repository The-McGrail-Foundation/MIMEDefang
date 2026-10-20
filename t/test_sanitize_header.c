#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../mimedefang.h"

#define NUM_TESTS 15

static int test_num = 0;

static void
check_value(const char *label, const char *input, const char *expected)
{
    char *out = sanitize_header_value(input);
    int ok = out && !strcmp(out, expected);

    test_num++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", test_num, label);
    if (!ok) {
	printf("# expected: \"%s\"\n# got:      \"%s\"\n", expected, out ? out : "(null)");
    }
    free(out);
}

static void
check_name(const char *label, const char *name, int expected)
{
    int ok = (valid_header_name(name) == expected);

    test_num++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", test_num, label);
}

int
main(void)
{
    printf("1..%d\n", NUM_TESTS);

    check_value("plain value unchanged", "hello world", "hello world");
    check_value("empty value", "", "");
    check_value("CR dropped", "a\rb", "ab");
    check_value("folded value kept", "a\n\tb", "a\n\tb");
    check_value("folded with space kept", "a\r\n b", "a\n b");
    check_value("bare LF folded", "a\nX-Injected: yes", "a\n\tX-Injected: yes");
    check_value("CRLF folded", "a\r\nX-Injected: yes", "a\n\tX-Injected: yes");
    check_value("blank line collapsed", "a\n\nbody", "a\n\tbody");
    check_value("trailing newline dropped", "a\n", "a");
    check_value("trailing CRLF dropped", "a\r\n\r\n", "a");

    check_name("valid name", "X-Spam-Score", 1);
    check_name("empty name", "", 0);
    check_name("name with colon", "X-Foo:", 0);
    check_name("name with space", "X Foo", 0);
    check_name("name with newline", "X-Foo\nX-Bar", 0);

    return 0;
}

#include <stdio.h>
#include <string.h>
#include "../json_out.h"

#define NUM_TESTS 9

static int test_num = 0;

static void
check(const char *label, const char *got, const char *expected)
{
    test_num++;
    if (got && expected && strcmp(got, expected) == 0) {
        printf("ok %d - %s\n", test_num, label);
    } else if (!got && !expected) {
        printf("ok %d - %s\n", test_num, label);
    } else {
        printf("not ok %d - %s\n", test_num, label);
        printf("# expected: %s", expected ? expected : "(null)\n");
        printf("# got:      %s", got ? got : "(null)\n");
    }
}

int
main(void)
{
    json_writer jw;
    int i;

    printf("1..%d\n", NUM_TESTS);

    json_init(&jw);
    json_obj_begin(&jw, NULL);
    json_obj_end(&jw);
    check("empty object", json_finish(&jw), "{}\n");
    json_free(&jw);

    json_init(&jw);
    json_obj_begin(&jw, NULL);
    json_int(&jw, "a", 1);
    json_int(&jw, "b", -2);
    json_bool(&jw, "c", 1);
    json_str(&jw, "d", NULL);
    json_obj_end(&jw);
    check("scalars and commas", json_finish(&jw),
          "{\"a\":1,\"b\":-2,\"c\":true,\"d\":null}\n");
    json_free(&jw);

    json_init(&jw);
    json_obj_begin(&jw, NULL);
    json_str(&jw, "s", "q\"b\\n\nt\tc\001");
    json_obj_end(&jw);
    check("escaping", json_finish(&jw),
          "{\"s\":\"q\\\"b\\\\n\\nt\\tc\\u0001\"}\n");
    json_free(&jw);

    json_init(&jw);
    json_obj_begin(&jw, NULL);
    json_str(&jw, "s", "100%41");
    json_obj_end(&jw);
    check("percent is escaped", json_finish(&jw),
          "{\"s\":\"100\\u002541\"}\n");
    json_free(&jw);

    json_init(&jw);
    json_obj_begin(&jw, NULL);
    json_str(&jw, "s", "caf\xc3\xa9");
    json_obj_end(&jw);
    check("UTF-8 passthrough", json_finish(&jw),
          "{\"s\":\"caf\xc3\xa9\"}\n");
    json_free(&jw);

    json_init(&jw);
    json_obj_begin(&jw, NULL);
    json_arr_begin(&jw, "x");
    json_int(&jw, NULL, 1);
    json_obj_begin(&jw, NULL);
    json_dbl(&jw, "f", 1.26, 1);
    json_obj_end(&jw);
    json_arr_begin(&jw, NULL);
    json_arr_end(&jw);
    json_arr_end(&jw);
    json_int(&jw, "y", 2);
    json_obj_end(&jw);
    check("nesting", json_finish(&jw),
          "{\"x\":[1,{\"f\":1.3},[]],\"y\":2}\n");
    json_free(&jw);

    json_init(&jw);
    json_arr_begin(&jw, NULL);
    json_dbl(&jw, NULL, 0.0 / 0.0 * 0.0, 2);
    json_dbl(&jw, NULL, 1e308 * 10.0, 2);
    json_arr_end(&jw);
    check("NaN and Inf become 0", json_finish(&jw), "[0.00,0.00]\n");
    json_free(&jw);

    json_init(&jw);
    json_obj_begin(&jw, NULL);
    check("unbalanced is an error", json_finish(&jw), NULL);
    json_free(&jw);

    /* Large output must spill out of the static dynbuf storage */
    json_init(&jw);
    json_arr_begin(&jw, NULL);
    for (i = 0; i < 5000; i++) {
        json_int(&jw, NULL, i);
    }
    json_arr_end(&jw);
    {
        char const *out = json_finish(&jw);
        check("large output",
              (out && strlen(out) > 20000 &&
               strncmp(out + strlen(out) - 7, ",4999]\n", 7) == 0) ? "ok" : "bad",
              "ok");
    }
    json_free(&jw);

    return 0;
}

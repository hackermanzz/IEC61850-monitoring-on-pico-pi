/*
 * The Pico SDK 2.3.1 C headers spell compile-time assertions as
 * `static_assert`, which is not a C99 keyword. Keep the analyzer target on
 * C99 by mapping those SDK assertions to equivalent C99 typedef checks.
 */
#ifndef C99_STATIC_ASSERT_COMPAT_H
#define C99_STATIC_ASSERT_COMPAT_H

#define C99_JOIN_INNER(left, right) left##right
#define C99_JOIN(left, right) C99_JOIN_INNER(left, right)
/* The Pico SDK token must retain this spelling for its C headers. */
// NOLINTNEXTLINE(readability-identifier-naming): Pico SDK compatibility token.
#define static_assert(condition, message)                                      \
    typedef char C99_JOIN(c99_static_assert_at_line_,                          \
                          __LINE__)[(condition) ? 1 : -1]

#endif

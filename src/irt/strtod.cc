
#include <stdlib.h>
#include <locale.h>

extern "C" float strtof_l(const char* __restrict s,
                          char** __restrict p,
                          locale_t) {
  return strtof(s, p);
}

extern "C" double strtod_l(const char* __restrict s,
                           char** __restrict p,
                           locale_t) {
  return strtod(s, p);
}

extern "C" long double strtold_l(const char* __restrict s,
                                 char** __restrict p,
                                 locale_t) {
  return strtold(s, p);
}

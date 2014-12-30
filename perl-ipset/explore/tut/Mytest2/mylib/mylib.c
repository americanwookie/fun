#include <stdlib.h>
#include "./mylib.h"

double
foo(int a, long b, const char *c)
{
  return (a + b + atof(c) + TESTVAL);
}

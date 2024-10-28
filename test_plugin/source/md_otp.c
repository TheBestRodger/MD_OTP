
#include <stdio.h>
#include <krb5.h>

#include "md_otp.h"
#include "md_attrset.h"
int main()
{
  com_err("bla b la", 0, "test plugin loaded 1 2 3");
  printf("test plugin\n");
  //com_err("bla b la", 0, md_krad_attrset_copy(NULL, NULL));
  // int* pa;
  // pa = k5calloc(1, sizeof(int), 0);
  return 0;
}
#include "md_otp.h"

int main()
{
    print_msg_from_kdc(NULL, 0);

    com_err("otp", 0, "Loaded");

    return 0;
}
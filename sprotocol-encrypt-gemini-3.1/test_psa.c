#include <psa/crypto.h>
#include <stdio.h>
int main() {
    psa_crypto_init();
    printf("PSA Crypto Init done.\n");
    return 0;
}

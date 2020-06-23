#include <stdlib.h>
#include <string.h>

char *b64_encode(const unsigned char *in, size_t len);
int b64_decode(const char *in, unsigned char *out, size_t outlen);
size_t b64_encoded_size(size_t inlen);
size_t b64_decoded_size(const char *in);

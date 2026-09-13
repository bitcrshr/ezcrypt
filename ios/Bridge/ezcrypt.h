#ifndef EZCRYPT_H
#define EZCRYPT_H
#include <stdint.h>
#include <stddef.h>
typedef int32_t (*ezcrypt_hardware_callback)(void *context, uint32_t operation, const uint8_t *input, size_t input_len, uint8_t *output, size_t capacity);
char *ezcrypt_call(const uint8_t *input, size_t length, const uint8_t *secret, size_t secret_len, ezcrypt_hardware_callback callback, void *context);
void ezcrypt_free(char *output);
#endif

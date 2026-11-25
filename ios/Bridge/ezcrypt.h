#ifndef EZCRYPT_H
#define EZCRYPT_H
#include <stdint.h>
#include <stddef.h>
typedef int32_t (*ezcrypt_hardware_callback)(void *context, uint32_t operation, const uint8_t *input, size_t input_len, uint8_t *output, size_t capacity);
char *ezcrypt_call(const uint8_t *input, size_t length, const uint8_t *secret, size_t secret_len, ezcrypt_hardware_callback callback, void *context);
void ezcrypt_free(char *output);

// Link delivery. One handle per delivery attempt; cancelling it is permanent.
typedef struct ezcrypt_link ezcrypt_link;
ezcrypt_link *ezcrypt_link_new(void);
// Blocks until the machine answers, the delivery fails, or the handle is cancelled.
// Input: {"offer":"<url>","payload":{...}}. Output: {"ok":{"outcome":"ok"|"error","message":...}}
// or {"error":...}; cancellation gives {"error":"Cancelled"}. Call it off the main thread,
// never from inside a Rust async runtime. Free the result with ezcrypt_free.
char *ezcrypt_link_deliver(ezcrypt_link *link, const uint8_t *input, size_t length); // blocking; free with ezcrypt_free
void ezcrypt_link_cancel(ezcrypt_link *link);  // thread-safe; deliver returns {"error":"Cancelled"}
// Must not be called while ezcrypt_link_deliver or ezcrypt_link_cancel on this handle is running:
// cancel, wait for deliver to return, then free.
void ezcrypt_link_free(ezcrypt_link *link);
#endif

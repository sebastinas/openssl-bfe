#ifndef HEADER_FS_0RTT_KEX_H
#define HEADER_FS_0RTT_KEX_H

#include <openssl/opensslconf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { FS_UNKNOWN, TBFE_BBG, BFE_BF } FS0RTT_impl;

typedef struct FS0RTT_pkey_st FS0RTT_pkey_t;
typedef struct FS0RTT_skey_st FS0RTT_skey_t;

FS0RTT_pkey_t* FS0RTT_new_pkey(FS0RTT_impl impl, const char* hostname);
FS0RTT_pkey_t* FS0RTT_load_pkey_from_file(const char* filename);
int FS0RTT_save_pkey_to_file(const char* filename, FS0RTT_pkey_t* pkey);
bool FS0RTT_pkey_matches_hostname(FS0RTT_pkey_t* pkey, const char* hostname);
void FS0RTT_free_pkey(FS0RTT_pkey_t* pkey);

FS0RTT_skey_t* FS0RTT_new_skey(FS0RTT_impl impl);
void FS0RTT_free_skey(FS0RTT_skey_t* skey);
int FS0RTT_load_skey_pkey_from_file(const char* filename, FS0RTT_skey_t** skey, FS0RTT_pkey_t** pkey);
int FS0RTT_save_skey_pkey_to_file(const char* filename, FS0RTT_skey_t* skey, FS0RTT_pkey_t* pkey);
int FS0RTT_generate_keys(FS0RTT_impl impl, const char* hostname, FS0RTT_skey_t** skey, FS0RTT_pkey_t** pkey);

int FS0RTT_enc(FS0RTT_pkey_t* pkey, uint64_t interval, uint8_t** ctxt, size_t* ctxt_size,
               uint8_t** key, size_t* key_size);
int FS0RTT_dec(FS0RTT_skey_t* skey, FS0RTT_pkey_t* pkey, uint64_t interval, const uint8_t* ctxt,
               size_t ctxt_size, uint8_t** key, size_t* key_size);
int FS0RTT_punc_interval(FS0RTT_skey_t* skey, FS0RTT_pkey_t* pkey, uint64_t interval);

#ifdef __cplusplus
}
#endif

#endif

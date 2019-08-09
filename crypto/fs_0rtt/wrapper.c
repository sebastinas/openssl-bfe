#include <assert.h>
#include <endian.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/fs0rttkex.h>

#if defined(WITH_DJSS)
#include <djss18bfebbg/DJSS_18_BFE_BBG.h>
#include <djss18bfebbg/DJSS_18_BFE_BBG_util.h>
#endif
#include <bfe-bf/bfe-bf.h>

#define BFE_BBG_NUM_LEVELS 4
#define BFE_BBG_MAX_DEPTH (BFE_BBG_NUM_LEVELS + 2)
#define BFE_BBG_BLOOMFILTER_SIZE 1000
#define BFE_BBG_CELL_SIZE 4
#define BFE_BBG_NUM_HASH 4

struct FS0RTT_skey_st {
  union {
#if defined(WITH_DJSS)
    djss18_bfe_bbg_secret_key_t bfebbg;
#endif
    bfe_bf_secret_key_t bfebf;
  };
  FS0RTT_impl impl;
};

struct FS0RTT_pkey_st {
  union {
#if defined(WITH_DJSS)
    djss18_bfe_bbg_public_key_t bfebbg;
#endif
    bfe_bf_public_key_t bfebf;
  };
  char* hostname;
  FS0RTT_impl impl;
};

__attribute__((constructor)) static void init(void) {
#if defined(WITH_DJSS)
  djss18_bfe_bbg_init();
#endif
}

__attribute__((destructor)) static void deinit(void) {
#if defined(WITH_DJSS)
  djss18_bfe_bbg_clean();
#endif
}

static uint8_t* mmap_whole_file(int fd, size_t* size) {
  struct stat sb;
  fstat(fd, &sb);

  uint8_t* data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (data == MAP_FAILED) {
    return NULL;
  }

  *size = sb.st_size;
  return data;
}

static bool read_uint32(uint32_t* v, const uint8_t** data, size_t* size) {
  if (*size < sizeof(uint32_t)) {
    return false;
  }

  memcpy(v, *data, sizeof(uint32_t));
  *v = le32toh(*v);

  *data += sizeof(uint32_t);
  *size -= sizeof(uint32_t);

  return true;
}

static bool write_uint32(FILE* f, uint32_t v) {
  v = htole32(v);
  return fwrite(&v, sizeof(uint32_t), 1, f) == 1;
}

static bool parse_pkey(const uint8_t** d, size_t* s, FS0RTT_pkey_t* pkey) {
  const uint8_t* data = *d;
  size_t file_size    = *s;

  /* load impl */
  uint32_t impl = 0;
  if (!read_uint32(&impl, &data, &file_size)) {
    return false;
  }

  /* load hostname */
  uint32_t hostname_size = 0;
  if (!read_uint32(&hostname_size, &data, &file_size) || !hostname_size) {
    return false;
  }

  if (file_size < hostname_size) {
    return false;
  }
  const char* hostname = (const char*)data;

  data += hostname_size;
  file_size -= hostname_size;

  /* load public key */
  uint32_t pkey_size = 0;
  if (!read_uint32(&pkey_size, &data, &file_size) || !pkey_size) {
    return false;
  }

  if (file_size < pkey_size) {
    return false;
  }

  switch (impl) {
#if defined(WITH_DJSS)
  case TBFE_BBG:
    djss18_bfe_bbg_public_key_null(pkey->bfebbg);
    djss18_bfe_bbg_public_key_new_deserialize(pkey->bfebbg, data);
    if (djss18_bfe_bbg_deserialize_public_key(pkey->bfebbg, data) != RLC_OK) {
      return false;
    }

    int valid = 0;
    if (djss18_bfe_bbg_public_key_is_valid(&valid, pkey->bfebbg) || !valid) {
      return false;
    }
    break;
#endif

  case BFE_BF:
    if (bfe_bf_public_key_deserialize(&pkey->bfebf, data)) {
      return false;
    }
    break;

  default:
    return false;
  }

  data += pkey_size;
  file_size -= pkey_size;

  pkey->hostname = OPENSSL_strndup(hostname, hostname_size);
  pkey->impl     = impl;

  *d = data;
  *s = file_size;

  return true;
}

static bool write_pkey(FILE* f, const FS0RTT_pkey_t* pkey) {
  /* write impl */
  if (!write_uint32(f, pkey->impl)) {
    return false;
  }

  /* write hostname */
  const uint32_t hostname_size = strlen(pkey->hostname);
  if (!write_uint32(f, hostname_size)) {
    return false;
  }

  if (fwrite(pkey->hostname, hostname_size, 1, f) != 1) {
    return false;
  }

  /* write public key */
  switch (pkey->impl) {
#if defined(WITH_DJSS)
  case TBFE_BBG:
    {
      const uint32_t pkey_size = djss18_bfe_bbg_get_public_key_size(pkey->bfebbg);
      if (!write_uint32(f, pkey_size)) {
        return false;
      }

      uint8_t* serialized = NULL;
      djss18_bfe_bbg_serialize_public_key(&serialized, pkey->bfebbg);
      if (fwrite(serialized, pkey_size, 1, f) != 1) {
        free(serialized);
        return false;
      }
      free(serialized);
      break;
    }
#endif

  case BFE_BF:
    {
      const uint32_t pkey_size = bfe_bf_public_key_size();
      if (!write_uint32(f, pkey_size)) {
        return false;
      }

      uint8_t* serialized = malloc(pkey_size);
      bfe_bf_public_key_serialize(serialized, &pkey->bfebf);
      if (fwrite(serialized, pkey_size, 1, f) != 1) {
        free(serialized);
        return false;
      }
      free(serialized);
      break;
    }

  default:
    return false;
  }

  return true;
}

static bool parse_skey(const uint8_t** d, size_t* s, FS0RTT_impl impl, FS0RTT_skey_t* skey) {
  const uint8_t* data = *d;
  size_t file_size    = *s;

  /* load secret key */
  if (file_size < sizeof(uint32_t)) {
    return false;
  }

  /* load public key */
  uint32_t skey_size = 0;
  if (!read_uint32(&skey_size, &data, &file_size) || !skey_size) {
    return false;
  }

  if (file_size < skey_size) {
    return false;
  }

  switch (impl) {
#if defined(WITH_DJSS)
  case TBFE_BBG:
    djss18_bfe_bbg_secret_key_null(skey->bfebbg);
    djss18_bfe_bbg_secret_key_new_deserialize(skey->bfebbg, data);
    if (djss18_bfe_bbg_deserialize_secret_key(skey->bfebbg, data) != RLC_OK) {
      return false;
    }

    int valid = 0;
    if (djss18_bfe_bbg_secret_key_is_valid(&valid, skey->bfebbg) || !valid) {
      return false;
    }
    break;
#endif

  case BFE_BF:
    if (bfe_bf_secret_key_deserialize(&skey->bfebf, data)) {
      return false;
    }
    break;

  default:
    return false;
  }

  data += skey_size;
  file_size -= skey_size;

  skey->impl     = impl;

  *d = data;
  *s = file_size;

  return true;
}

static bool write_skey(FILE* f, FS0RTT_skey_t* skey) {
  /* write secret key */
  switch (skey->impl) {
#if defined(WITH_DJSS)
  case TBFE_BBG:
    {
      const uint32_t skey_size = djss18_bfe_bbg_get_secret_key_size(skey->bfebbg);
      if (!write_uint32(f, skey_size)) {
        return false;
      }

      uint8_t* serialized = NULL;
      djss18_bfe_bbg_serialize_secret_key(&serialized, skey->bfebbg);
      if (fwrite(serialized, skey_size, 1, f) != 1) {
        free(serialized);
        return false;
      }
      free(serialized);
      break;
    }
#endif

  case BFE_BF:
    {
      const uint32_t skey_size = bfe_bf_secret_key_size(&skey->bfebf);
      if (!write_uint32(f, skey_size)) {
        return false;
      }

      uint8_t* serialized = malloc(skey_size);
      bfe_bf_secret_key_serialize(serialized, &skey->bfebf);
      if (fwrite(serialized, skey_size, 1, f) != 1) {
        free(serialized);
        return false;
      }
      free(serialized);
      break;
    }

  default:
    return false;
  }

  return true;
}

FS0RTT_pkey_t* FS0RTT_new_pkey(FS0RTT_impl impl, const char* hostname) {
  if (!hostname) {
    return NULL;
  }

  FS0RTT_pkey_t* pkey = OPENSSL_zalloc(sizeof(FS0RTT_pkey_t));
  if (!pkey) {
    return NULL;
  }

  switch (impl) {
#if defined(WITH_DJSS)
  case TBFE_BBG:
    djss18_bfe_bbg_public_key_null(pkey->bfebbg);
    djss18_bfe_bbg_public_key_new(pkey->bfebbg, BFE_BBG_MAX_DEPTH);
    break;
#endif

  case BFE_BF:
    bfe_bf_init_public_key(&pkey->bfebf);
    break;

  default:
    OPENSSL_free(pkey);
    return NULL;
  }

  pkey->hostname = OPENSSL_strdup(hostname);
  pkey->impl = impl;

  return pkey;
}

FS0RTT_pkey_t* FS0RTT_load_pkey_from_file(const char* filename) {
  if (!filename) {
    return NULL;
  }

  const int fd = open(filename, O_RDONLY);
  if (fd == -1) {
    return NULL;
  }

  size_t orig_file_size = 0;
  uint8_t* orig_data = mmap_whole_file(fd, &orig_file_size);
  if (!orig_data) {
    close(fd);
    return NULL;
  }
  const uint8_t* data = orig_data;
  size_t file_size = orig_file_size;

  FS0RTT_pkey_t* pkey = OPENSSL_zalloc(sizeof(FS0RTT_pkey_t));
  if (!pkey || !parse_pkey(&data, &file_size, pkey)) {
    goto error;
  }

  goto done;

error:
  FS0RTT_free_pkey(pkey);
  pkey = NULL;

done:
  munmap(orig_data, orig_file_size);
  close(fd);
  return pkey;
}

int FS0RTT_save_pkey_to_file(const char* filename, FS0RTT_pkey_t* pkey)
{
  if (!filename || !pkey) {
    return 2;
  }

  FILE* file = fopen(filename, "w");
  if (!file) {
    return 1;
  }

  if (!write_pkey(file, pkey)) {
    fclose(file);
    return 1;
  }
  fclose(file);

  return 0;
}

void FS0RTT_free_pkey(FS0RTT_pkey_t* pkey) {
  if (!pkey) {
    return;
  }

  OPENSSL_free(pkey->hostname);
  pkey->hostname = NULL;

  switch (pkey->impl) {
#if defined(WITH_DJSS)
  case TBFE_BBG:
    djss18_bfe_bbg_public_key_free(pkey->bfebbg);
    break;
#endif

  case BFE_BF:
    bfe_bf_clear_public_key(&pkey->bfebf);
    break;

  default:
    assert(0);
  }

  OPENSSL_free(pkey);
}

bool FS0RTT_pkey_matches_hostname(FS0RTT_pkey_t* pkey, const char* hostname)
{
  if (!pkey || !hostname) {
    return false;
  }

  return strcmp(pkey->hostname, hostname) == 0;
}

FS0RTT_skey_t* FS0RTT_new_skey(FS0RTT_impl impl) {
  FS0RTT_skey_t* skey = OPENSSL_zalloc(sizeof(FS0RTT_skey_t));
  if (!skey) {
    return NULL;
  }

  switch (impl) {
#if defined(WITH_DJSS)
  case TBFE_BBG:
    djss18_bfe_bbg_secret_key_null(skey->bfebbg);
    djss18_bfe_bbg_secret_key_new(skey->bfebbg, BFE_BBG_BLOOMFILTER_SIZE, BFE_BBG_CELL_SIZE,
                                  BFE_BBG_NUM_HASH);
    break;
#endif

  case BFE_BF:
    bfe_bf_init_secret_key(&skey->bfebf);
    break;

  default:
    OPENSSL_free(skey);
    return NULL;
  }
  skey->impl = impl;

  return skey;
}

void FS0RTT_free_skey(FS0RTT_skey_t* skey) {
  if (!skey) {
    return;
  }

  switch (skey->impl) {
#if defined(WITH_DJSS)
  case TBFE_BBG:
    djss18_bfe_bbg_secret_key_free(skey->bfebbg);
    break;
#endif

  case BFE_BF:
    bfe_bf_clear_secret_key(&skey->bfebf);
    break;

  default:
    assert(0);
  }

  OPENSSL_free(skey);
}

int FS0RTT_load_skey_pkey_from_file(const char* filename, FS0RTT_skey_t** skey, FS0RTT_pkey_t** pkey) {
  if (!filename || !skey || !pkey) {
    return 2;
  }

  const int fd = open(filename, O_RDONLY);
  if (fd == -1) {
    return 1;
  }

  size_t orig_file_size = 0;
  uint8_t* orig_data = mmap_whole_file(fd, &orig_file_size);
  if (!orig_data) {
    close(fd);
    return 1;
  }
  const uint8_t* data = orig_data;
  size_t file_size = orig_file_size;

  int ret = 0;
  *pkey = OPENSSL_zalloc(sizeof(FS0RTT_pkey_t));
  *skey = OPENSSL_zalloc(sizeof(FS0RTT_skey_t));
  if (!*pkey || !*skey || !parse_pkey(&data, &file_size, *pkey) || !parse_skey(&data, &file_size, (*pkey)->impl, *skey)) {
    ret = 1;
    goto error;
  }

  goto done;

error:
  FS0RTT_free_pkey(*pkey);
  *pkey = NULL;

  FS0RTT_free_skey(*skey);
  *skey = NULL;

done:
  munmap(orig_data, orig_file_size);
  close(fd);
  return ret;
}

int FS0RTT_save_skey_pkey_to_file(const char* filename, FS0RTT_skey_t* skey, FS0RTT_pkey_t* pkey)
{
  if (!filename || !skey || !pkey) {
    return 2;
  }

  FILE* file = fopen(filename, "w");
  if (!file) {
    return 1;
  }

  if (!write_pkey(file, pkey) || !write_skey(file, skey)) {
    fclose(file);
    return 1;
  }
  fclose(file);

  return 0;
}

int FS0RTT_generate_keys(FS0RTT_impl impl, const char* hostname, FS0RTT_skey_t** skey, FS0RTT_pkey_t** pkey) {
  if (!hostname || !skey || !pkey) {
    return 2;
  }

  *pkey = FS0RTT_new_pkey(impl, hostname);
  *skey = FS0RTT_new_skey(impl);
  if (!*pkey || !*skey) {
    goto error;
  }

  switch (impl) {
#if defined(WITH_DJSS)
  case TBFE_BBG:
    if (djss18_bfe_bbg_key_gen((*pkey)->bfebbg, (*skey)->bfebbg, BFE_BBG_BLOOMFILTER_SIZE, BFE_BBG_NUM_HASH, BFE_BBG_NUM_LEVELS, 0) != RLC_OK) {
      goto error;
    }
    break;
#endif

  case BFE_BF:
    if (bfe_bf_keygen(&(*pkey)->bfebf, &(*skey)->bfebf, 32, 1 << 19, 0.0009765625)) {
      goto error;
    }
    break;

    default:
      assert(0);
  }

  return 0;

error:
  FS0RTT_free_pkey(*pkey);
  *pkey = NULL;

  FS0RTT_free_skey(*skey);
  *skey = NULL;
  return 1;
}

int FS0RTT_enc(FS0RTT_pkey_t* pkey, uint64_t interval, uint8_t** ctxt, size_t* ctxt_size,
               uint8_t** key, size_t* key_size) {
  if (!pkey || !ctxt || !ctxt_size || !key || !key_size) {
    return 2;
  }

  switch (pkey->impl) {
#if defined(WITH_DJSS)
  case TBFE_BBG: {
    /* convert interval to identity */
    bbg05_identity_t tau;
    bbg05_identity_null(tau);
    index_to_identity(&tau, interval, BFE_BBG_NUM_LEVELS);

    djss18_bfe_bbg_ciphertext_t ciphertext;
    djss18_bfe_bbg_ciphertext_null(ciphertext);
    djss18_bfe_bbg_ciphertext_new(ciphertext, vector_size(pkey->bfebbg->H), tau->depth);

    /* sample and encapsulate key */
    int ret = djss18_bfe_bbg_encapsulate(key, ciphertext, pkey->bfebbg, tau);
    bbg05_identity_free(tau);

    if (ret != RLC_OK) {
      djss18_bfe_bbg_ciphertext_free(ciphertext);
      return 1;
    }
    *key_size = SECURITY_PARAMETER;

    /* serialize ciphertext */
    *ctxt_size = djss18_bfe_bbg_get_ciphertext_size(ciphertext);
    djss18_bfe_bbg_serialize_ciphertext(ctxt, ciphertext);
    djss18_bfe_bbg_ciphertext_free(ciphertext);
    break;
  }
#endif

  case BFE_BF: {
    bfe_bf_ciphertext_t ciphertext;
    bfe_bf_init_ciphertext(&ciphertext, &pkey->bfebf);

    *key_size = pkey->bfebf.key_size;
    *key = malloc(*key_size);
    if (!key || bfe_bf_encaps(&ciphertext, *key, &pkey->bfebf)) {
      return 1;
    }

    *ctxt_size = bfe_bf_ciphertext_size(&ciphertext);
    *ctxt = malloc(*ctxt_size);
    bfe_bf_ciphertext_serialize(*ctxt, &ciphertext);
    bfe_bf_clear_ciphertext(&ciphertext);
    break;
  }

  default:
    assert(0);
  }

  return 0;
}

int FS0RTT_dec(FS0RTT_skey_t* skey, FS0RTT_pkey_t* pkey, uint64_t interval, const uint8_t* ctxt,
               size_t ctxt_size, uint8_t** key, size_t* key_size) {
  if (!skey || !ctxt || !ctxt_size || !key || !key_size) {
    return 2;
  }

  switch (skey->impl) {
#if defined(WITH_DJSS)
  case TBFE_BBG: {
    djss18_bfe_bbg_ciphertext_t ciphertext;
    djss18_bfe_bbg_ciphertext_null(ciphertext);
    djss18_bfe_bbg_ciphertext_new_deserialize(ciphertext, ctxt);

    /* desearlize ciphertext */
    int ret = djss18_bfe_bbg_deserialize_ciphertext(ciphertext, ctxt);
    if (ret != RLC_OK) {
      djss18_bfe_bbg_ciphertext_free(ciphertext);
      return 1;
    }

    int valid = 0;
    ret = djss18_bfe_bbg_ciphertext_is_valid(&valid, ciphertext);
    if (ret != RLC_OK || !valid) {
      djss18_bfe_bbg_ciphertext_free(ciphertext);
      return 1;
    }

    bbg05_identity_t tau;
    bbg05_identity_null(tau);
    index_to_identity(&tau, interval, BFE_BBG_NUM_LEVELS);

    /* sample and encapsulate key */
    ret = djss18_bfe_bbg_decapsulate(key, ciphertext, skey->bfebbg, pkey->bfebbg, tau);
    bbg05_identity_free(tau);
    if (ret != RLC_OK) {
      return 1;
    }
    *key_size = SECURITY_PARAMETER;

    /* puncture ciphertext */
    djss18_bfe_bbg_puncture_ciphertext(skey->bfebbg, ciphertext);
    djss18_bfe_bbg_ciphertext_free(ciphertext);

    break;
  }
#endif

  case BFE_BF: {
    bfe_bf_ciphertext_t ciphertext;
    if (bfe_bf_ciphertext_deserialize(&ciphertext, ctxt)) {
      return 1;
    }

    *key_size = pkey->bfebf.key_size;
    *key = malloc(*key_size);
    if (!key || bfe_bf_decaps(*key, &pkey->bfebf, &skey->bfebf, &ciphertext)) {
      return 1;
    }

    /* puncutre ciphertext */
    bfe_bf_puncture(&skey->bfebf, &ciphertext);

    bfe_bf_clear_ciphertext(&ciphertext);
    break;
  }

  default:
    assert(0);
  }

  return 0;
}

int FS0RTT_punc_interval(FS0RTT_skey_t* skey, FS0RTT_pkey_t* pkey, uint64_t interval)
{
  if (!skey || !pkey) {
    return 2;
  }

  switch (skey->impl) {
#if defined(WITH_DJSS)
  case TBFE_BBG: {
    bbg05_identity_t tau;
    bbg05_identity_null(tau);
    index_to_identity(&tau, interval, BFE_BBG_NUM_LEVELS);

    /* puncture interval */
    const int ret = djss18_bfe_bbg_puncture_interval(skey->bfebbg, pkey->bfebbg, tau);
    bbg05_identity_free(tau);

    if (ret != RLC_OK) {
      return 1;
    }
    break;
  }
#endif

  default:
    assert(0);
  }

  return 0;
}

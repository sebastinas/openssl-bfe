#include <stdio.h>
#include <openssl/fs0rttkex.h>

#include "apps.h"
#include "progs.h"

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_PKEY, OPT_SKEY, OPT_HOSTNAME
} OPTION_CHOICE;

const OPTIONS fs0rtt_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"pkey", OPT_PKEY, 's', "public key file"},
    {"skey", OPT_SKEY, 's', "secret key file"},
    {"hostname", OPT_HOSTNAME, 's', "host name"},
    {NULL, OPT_EOF, 0x00, NULL}
};

int fs0rtt_main(int argc, char **argv)
{
  int ret         = 0;
  char* pkey_file = NULL;
  char* skey_file = NULL;
  char* hostname = NULL;

  FS0RTT_pkey_t* pkey = NULL;
  FS0RTT_skey_t* skey = NULL;

  char* prog = opt_progname(argv[0]);
  prog = opt_init(argc, argv, fs0rtt_options);
  OPTION_CHOICE o;
  while ((o = opt_next()) != OPT_EOF) {
    switch (o) {
    case OPT_EOF:
    case OPT_ERR:
    opthelp:
      BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
      goto end;
    case OPT_HELP:
      opt_help(fs0rtt_options);
      ret = 0;
      goto end;

    case OPT_PKEY:
      pkey_file = opt_arg();
      break;
    case OPT_SKEY:
      skey_file = opt_arg();
      break;
    case OPT_HOSTNAME:
      hostname = opt_arg();
    }
  }

  if (!pkey_file || !pkey_file) {
    BIO_printf(bio_err, "%s: Requires both -pkey and -skey\n", prog);
    goto opthelp;
  }

  ret = FS0RTT_generate_keys(BFE_BF, hostname ? hostname : "localhost", &skey, &pkey);
  if (ret != 0) {
    BIO_printf(bio_err, "%s: Unable to generate keys: %d\n", prog, ret);
    goto end;
  }

  ret = FS0RTT_save_skey_pkey_to_file(skey_file, skey, pkey);
  if (ret != 0) {
    BIO_printf(bio_err, "%s: Unable to save secret key to '%s': %d\n", prog, skey_file, ret);
    goto end;
  }

  ret = FS0RTT_save_pkey_to_file(pkey_file, pkey);
  if (ret != 0) {
    BIO_printf(bio_err, "%s: Unable to save public key to '%s': %d\n", prog, pkey_file, ret);
    goto end;
  }

end:
  FS0RTT_free_skey(skey);
  FS0RTT_free_pkey(pkey);

  return ret;
}

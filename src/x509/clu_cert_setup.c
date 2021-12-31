/* clu_cert_setup.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <stdio.h>
#include <unistd.h>

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/x509/clu_cert.h>
#include <wolfclu/x509/clu_parse.h>

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_certSetup(int argc, char** argv)
{
    int idx;
    int ret = WOLFCLU_SUCCESS;
    int textFlag    = 0;   /* does user desire human readable cert info */
    int textPubkey  = 0;   /* does user desire human readable pubkey info */
    int nooutFlag   = 0;   /* are we outputting a file */
    int inderFlag   = 0;   /* is the incoming file in der format */
    int inpemFlag   = 1;   /* is the incoming file in pem format */
    int outderFlag  = 0;   /* is the output file in der format */
    int outpemFlag  = 1;   /* is the output file in pem format */
    int inFileFlag  = 0;   /* set if passing in file argument */
    int outFileFlag = 0;   /* set if passing out file argument */
    int silentFlag  = 0;   /* set to disable echo to command line */

    char* inFile  = NULL;   /* pointer to the inFile name */
    char* outFile = NULL;   /* pointer to the outFile name */
    int   inForm  = PEM_FORM; /* the input format */
    int   outForm = PEM_FORM; /* the output format */

    WOLFSSL_BIO* in  = NULL;
    WOLFSSL_BIO* out = NULL;
    WOLFSSL_X509* x509 = NULL;

/*---------------------------------------------------------------------------*/
/* help */
/*---------------------------------------------------------------------------*/
    if (wolfCLU_checkForArg("-h", 2, argc, argv) > 0) {
        wolfCLU_certHelp();
        return WOLFCLU_SUCCESS;
    }

/*---------------------------------------------------------------------------*/
/* text */
/*---------------------------------------------------------------------------*/
    if (wolfCLU_checkForArg("-text", 5, argc, argv) > 0) {
        /* set flag for converting to human readable.
         */
        textFlag = 1;
    } /* Optional flag do not return error */
/*---------------------------------------------------------------------------*/
/* pubkey */
/*--------------------------------------------------------------------------*/
    if (wolfCLU_checkForArg("-pubkey", 7, argc, argv) > 0) {
        /* set flag for converting to human readable.
         */
        textPubkey = 1;
    } /* Optional flag do not return error */
/*---------------------------------------------------------------------------*/
/* inForm pem/der/??OTHER?? */
/*---------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS) {
        idx = wolfCLU_checkForArg("-inform", 7, argc, argv);
        if (idx > 0) {
            inForm = wolfCLU_checkInform(argv[idx+1]);
            if (inForm == DER_FORM) {
                inpemFlag = 0;
                inderFlag = 1;
            }
        }
    }

/*---------------------------------------------------------------------------*/
/* outForm pem/der/??OTHER?? */
/*---------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS) {
        idx = wolfCLU_checkForArg("-outform", 8, argc, argv);
        if (idx > 0) {
            outForm = wolfCLU_checkOutform(argv[idx+1]);
            if (outForm == DER_FORM) {
                outpemFlag = 0;
                outderFlag = 1;
            }
        }
    }



/*---------------------------------------------------------------------------*/
/* in file */
/*---------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS) {
        idx = wolfCLU_checkForArg("-in", 3, argc, argv);
        if (idx > 0) {
            /* set flag for in file and flag for input file OK if exists
             * check for error case below. If no error then read in file */
            inFile = argv[idx+1];
            in = wolfSSL_BIO_new_file(inFile, "rb");
            if (in == NULL) {
                WOLFCLU_LOG(WOLFCLU_E0, "ERROR: in file \"%s\" does not exist",
                    inFile);
                ret = INPUT_FILE_ERROR;
            }
        }
        else {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (access(inFile, F_OK) != -1) {
            WOLFCLU_LOG(WOLFCLU_L0, "input file is \"%s\"", inFile);
            inFileFlag = 1;
        }
        else {
            WOLFCLU_LOG(WOLFCLU_E0, "ERROR: input file \"%s\" does not exist",
                    inFile);
            ret = INPUT_FILE_ERROR;
        }
    }
/*---------------------------------------------------------------------------*/
/* out file */
/*---------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS) {
        idx = wolfCLU_checkForArg("-out", 4, argc, argv);
        if (idx > 0) {
            /* set flag for out file, check for error case below. If no error
             * then write outFile */
            outFileFlag = 1;
            outFile = argv[idx+1];
        }

        if (idx < 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

/*---------------------------------------------------------------------------*/
/* noout */
/*---------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS &&
            wolfCLU_checkForArg("-noout", 6, argc, argv) > 0) {
        /* set flag for no output file */
        nooutFlag = 1;
    } /* Optional flag do not return error */
/*---------------------------------------------------------------------------*/
/* silent */
/*---------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS &&
            wolfCLU_checkForArg("-silent", 7, argc, argv) > 0) {
        /* set flag for converting to human readable.
         * return NOT_YET_IMPLEMENTED error
         */
        silentFlag = 1;
    } /* Optional flag do not return error */
/*---------------------------------------------------------------------------*/
/* END ARG PROCESSING */
/*---------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS) {
        if (inForm == PEM_FORM) {
            x509 = wolfSSL_PEM_read_bio_X509(in, NULL, NULL, NULL);
        }
        else if (inForm == DER_FORM) {
            x509 = wolfSSL_d2i_X509_bio(in, NULL);
        }

        if (x509 == NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "unable to parse input file");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* done with input file */
    wolfSSL_BIO_free(in);

    /* try to open output file if set */
    if (ret == WOLFCLU_SUCCESS && outFile != NULL) {
        out = wolfSSL_BIO_new_file(outFile, "wb");
        if (access(outFile, F_OK) != -1) {
            WOLFCLU_LOG(WOLFCLU_L0, "output file set: \"%s\"", outFile);
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "output file \"%s\"did not exist, it will"
                   " be created.", outFile);
        }
    }

    /* write to stdout if out is not set */
    if (ret == WOLFCLU_SUCCESS && out == NULL) {
        out = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (out == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (wolfSSL_BIO_set_fp(out, stdout, BIO_NOCLOSE)
                    != WOLFSSL_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    /* write out human readable text if set to */
    if (ret == WOLFCLU_SUCCESS && textFlag) {
        if (wolfSSL_X509_print(out, x509) != WOLFSSL_SUCCESS) {
            WOLFCLU_LOG(WOLFCLU_L0, "unable to print certificate out");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* write out public key if set to */
    if (ret == WOLFCLU_SUCCESS && textPubkey) {
        ret = wolfCLU_printX509PubKey(x509, out);
    }

    /* write out certificate */
    if (ret == WOLFCLU_SUCCESS && !nooutFlag) {
        if (outForm == PEM_FORM) {
            if (wolfSSL_PEM_write_bio_X509(out, x509) != WOLFSSL_SUCCESS) {
                WOLFCLU_LOG(WOLFCLU_L0, "unable to write certificate out");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else {
            if (wolfSSL_i2d_X509_bio(out, x509) != WOLFSSL_SUCCESS) {
                WOLFCLU_LOG(WOLFCLU_L0, "unable to write certificate out");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    wolfSSL_BIO_free(out);
    wolfSSL_X509_free(x509);
    return ret;
}


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

enum {
    IN_PEM_OUT_PEM  = 1,
    IN_PEM_OUT_DER  = 2,
    IN_DER_OUT_PEM  = 3,
    IN_DER_OUT_DER  = 4,
    IN_PEM_OUT_TEXT = 5,
    NOOUT_SET       = 6,
    OUT_PUB_TEXT    = 7,
};

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_certSetup(int argc, char** argv)
{
    int ret;
    int textFlag    = 0;   /* does user desire human readable cert info */
    int textPubkey  = 0;   /* does user desire human readable pubkey info */
    int nooutFlag   = 0;   /* are we outputting a file */
    int inderFlag   = 0;   /* is the incoming file in der format */
    int inpemFlag   = 0;   /* is the incoming file in pem format */
    int outderFlag  = 0;   /* is the output file in der format */
    int outpemFlag  = 0;   /* is the output file in pem format */
    int inFileFlag  = 0;   /* set if passing in file argument */
    int outFileFlag = 0;   /* set if passing out file argument */
    int silentFlag  = 0;   /* set to disable echo to command line */

    char* inFile  = NULL;   /* pointer to the inFile name */
    char* outFile = NULL;   /* pointer to the outFile name */
    int   inForm  = PEM_FORM; /* the input format */
    char* outForm;          /* the output format */


/*---------------------------------------------------------------------------*/
/* help */
/*---------------------------------------------------------------------------*/
    ret = wolfCLU_checkForArg("-h", 2, argc, argv);
    if (ret > 0) {
        wolfCLU_certHelp();
        return WOLFCLU_SUCCESS;
    }
/*---------------------------------------------------------------------------*/
/* text */
/*---------------------------------------------------------------------------*/
    ret = wolfCLU_checkForArg("-text", 5, argc, argv);
    if (ret > 0) {
        /* set flag for converting to human readable.
         */
        textFlag = 1;
    } /* Optional flag do not return error */
/*---------------------------------------------------------------------------*/
/* pubkey */
/*--------------------------------------------------------------------------*/
    ret = wolfCLU_checkForArg("-pubkey", 7, argc, argv);
    if (ret > 0) {
        /* set flag for converting to human readable.
         */
        textPubkey = 1;
    } /* Optional flag do not return error */
/*---------------------------------------------------------------------------*/
/* inForm pem/der/??OTHER?? */
/*---------------------------------------------------------------------------*/
    ret = wolfCLU_checkForArg("-inform", 7, argc, argv);
    if (ret > 0) {
        inForm = wolfCLU_checkInform(argv[ret+1]);
        if (inForm == PEM_FORM) {
            inpemFlag = 1;
        }
        else if (inForm == DER_FORM) {
            inderFlag = 1;
        }
        else {
            return inForm;
        }
    }
    else if (ret == 0) {
        /* assume is PEM if not set */
        inpemFlag = 1;
    }
    else {
        return ret;
    }

/*---------------------------------------------------------------------------*/
/* outForm pem/der/??OTHER?? */
/*---------------------------------------------------------------------------*/
    ret = wolfCLU_checkForArg("-outform", 8, argc, argv);
    if (ret > 0) {
        outForm = argv[ret+1];
        ret = wolfCLU_checkOutform(outForm);
        if (ret == PEM_FORM) {
            outpemFlag = 1;
        }
        else if (ret == DER_FORM) {
            outderFlag = 1;
        }
        else {
            return ret;
        }
    }
    else if (textFlag == 0 && textPubkey == 0) {
        return ret;
    }



/*---------------------------------------------------------------------------*/
/* in file */
/*---------------------------------------------------------------------------*/
    ret = wolfCLU_checkForArg("-in", 3, argc, argv);
    if (ret > 0) {
       /* set flag for in file and flag for input file OK if exists
        * check for error case below. If no error then read in file */
       inFile = argv[ret+1];
    }
    else {
        return ret;
    }

    if (access(inFile, F_OK) != -1) {
        WOLFCLU_LOG(WOLFCLU_L0, "input file is \"%s\"", inFile);
        inFileFlag = 1;
    }
    else {
        WOLFCLU_LOG(WOLFCLU_L0, "ERROR: input file \"%s\" does not exist", inFile);
        return INPUT_FILE_ERROR;
    }
/*---------------------------------------------------------------------------*/
/* out file */
/*---------------------------------------------------------------------------*/
    ret = wolfCLU_checkForArg("-out", 4, argc, argv);
    if (ret > 0) {
        /* set flag for out file, check for error case below. If no error
         * then write outFile */
        outFileFlag = 1;
        outFile = argv[ret+1];
    }
    else if (textFlag == 0 && textPubkey == 0) {
        return ret;
    }

    if (outFile != NULL) {
        if (access(outFile, F_OK) != -1) {
            WOLFCLU_LOG(WOLFCLU_L0, "output file set: \"%s\"", outFile);
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "output file \"%s\"did not exist, it will"
                   " be created.", outFile);
        }
    }
/*---------------------------------------------------------------------------*/
/* noout */
/*---------------------------------------------------------------------------*/
    ret = wolfCLU_checkForArg("-noout", 6, argc, argv);
    if (ret > 0) {
        /* set flag for no output file */
        nooutFlag = 1;
    } /* Optional flag do not return error */
/*---------------------------------------------------------------------------*/
/* silent */
/*---------------------------------------------------------------------------*/
    ret = wolfCLU_checkForArg("-silent", 7, argc, argv);
    if (ret > 0) {
        /* set flag for converting to human readable.
         * return NOT_YET_IMPLEMENTED error
         */
        silentFlag = 1;
    } /* Optional flag do not return error */
/*---------------------------------------------------------------------------*/
/* END ARG PROCESSING */
/*---------------------------------------------------------------------------*/
    ret = 0;
    switch (error_check(inpemFlag, inderFlag, outpemFlag, outderFlag,
                      textFlag, textPubkey, nooutFlag)) {
        case IN_PEM_OUT_PEM:
            if (inFileFlag) wolfCLU_inpemOutpem(inFile, outFile, silentFlag);
            else return INPUT_FILE_ERROR;
            break;
        case IN_PEM_OUT_DER:
            if (inFileFlag) wolfCLU_inpemOutder(inFile, outFile, silentFlag);
            else return INPUT_FILE_ERROR;
            break;
        case IN_DER_OUT_PEM:
            if (inFileFlag) wolfCLU_inderOutpem(inFile, outFile, silentFlag);
            else return INPUT_FILE_ERROR;
            break;
        case IN_DER_OUT_DER:
            if (inFileFlag) wolfCLU_inderOutder(inFile, outFile, silentFlag);
            else return INPUT_FILE_ERROR;
            break;
        case IN_PEM_OUT_TEXT:
            if (outFileFlag) {
                ret = wolfCLU_inpemOuttext(inFile, outFile, silentFlag);
            }
            else {
                WOLFCLU_LOG(WOLFCLU_L0, "Outfile not set, using stdout");
                outFile = (char*)"stdout";
                ret = wolfCLU_inpemOuttext(inFile, outFile, silentFlag);
            }
            break;
        case OUT_PUB_TEXT:
            ret = wolfCLU_printX509PubKey(inFile, inForm, outFile, silentFlag);
            break;
        case NOOUT_SET:
            break;
        default:
            WOLFCLU_LOG(WOLFCLU_L0, "Error case");
            ret = -1;
            break;
    }

    return ret;
}

/*
 * @arg inpemFlag: is inForm set to pem
 * @arg inderFlag: is inForm set to der
 * @arg outpemFlag: is outForm set to pem
 * @arg outderFlag: is outForm set to der
 */
int error_check(int inpemFlag, int inderFlag,
                int outpemFlag, int outderFlag,
                int textFlag, int textPubkey, int nooutFlag)
{
    int ret = USER_INPUT_ERROR;
    int tmp;

    ret = ( inpemFlag & inderFlag);
    if (ret) {
        WOLFCLU_LOG(WOLFCLU_L0, "ERROR: inForm set to both PEM and DER format");
        return USER_INPUT_ERROR;
    }
    ret = ( inpemFlag & outpemFlag);
    if (ret) {
        tmp = ret;
        ret = (tmp & nooutFlag);
        if (ret) {
            WOLFCLU_LOG(WOLFCLU_L0, "ERROR: noout set when output format is specified");
            return USER_INPUT_ERROR;
        }
        return IN_PEM_OUT_PEM;
   }
    ret = (inpemFlag & outderFlag);
    if (ret) {
        tmp = ret;
        ret = (tmp & nooutFlag);
        if (ret) {
            WOLFCLU_LOG(WOLFCLU_L0, "ERROR: noout set when output format is specified");
            return USER_INPUT_ERROR;
        }
        return IN_PEM_OUT_DER;
    }
    ret = (inderFlag & outpemFlag);
    if (ret) {
        tmp = ret;
        ret = (tmp & nooutFlag);
        if (ret) {
            WOLFCLU_LOG(WOLFCLU_L0, "ERROR: noout set when output format is specified");
            return USER_INPUT_ERROR;
        }
        return IN_DER_OUT_PEM;
    }
    ret = (inderFlag & outderFlag);
    if (ret) {
        tmp = ret;
        ret = (tmp & nooutFlag);
        if (ret) {
            WOLFCLU_LOG(WOLFCLU_L0, "ERROR: noout set when output format is specified");
            return USER_INPUT_ERROR;
        }
        return IN_DER_OUT_DER;
    }
    ret = (inpemFlag & textFlag);
    if (ret) {
        return IN_PEM_OUT_TEXT;
    }
    if (textPubkey) {
        return OUT_PUB_TEXT;
    }
    ret = (outderFlag & outpemFlag);
    if (ret) {
        WOLFCLU_LOG(WOLFCLU_L0, "ERROR: outForm set to both DER and PEM format");
        return USER_INPUT_ERROR;
    }
    if (!ret) {
        ret = USER_INPUT_ERROR;
        if ( !inpemFlag && !inderFlag) {
            WOLFCLU_LOG(WOLFCLU_L0, "ERROR: Failed to specify input format: -inform not set");
        }
        else {
            ret = (inderFlag & nooutFlag) | (inpemFlag & nooutFlag);
            if (ret) {
                return NOOUT_SET;
            }
            else {
                WOLFCLU_LOG(WOLFCLU_L0, "ERROR: Failed to specify -outform or -noout");
            }
        }
    }
    return ret;
}

/* clu_parse.h
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

#ifndef WOLFCLU_PARSE_H
#define WOLFCLU_PARSE_H

/* a helper function for wolfCLU_parse_file */
int wolfCLU_inpemOutpem(char* inFile, char* outFile, int silentFlag);
/* a helper function for wolfCLU_parse_file */
int wolfCLU_inpemOutder(char* inFile, char* outFile, int silentFlag);
/* a helper function for wolfCLU_parse_file */
int wolfCLU_inderOutpem(char* inFile, char* outFile, int silentFlag);
/* a helper function for wolfCLU_parse_file */
int wolfCLU_inderOutder(char* inFile, char* outFile, int silentFlag);
/* a helper function for wolfCLU_parse_file */
int wolfCLU_inpemOuttext(char* inFile, char* outFile, int silentFlag);

/**
 * @brief Function to print out DER public key
 *
 * @param bio the bio to print to
 * @param der der buffer to print out
 * @param derSz size of 'der' buffer
 *
 * @return returns 0 on success
 */
int wolfCLU_printDerPubKey(WOLFSSL_BIO* bio, unsigned char* der, int derSz);

/**
 * @brief prints out the public key from a certificate
 *
 * @param infile file to read from
 * @param inform PEM_FORM/DER_FORM of input
 * @param outFile name of the file to write to
 * @param silentFlag if should be silent instead of printout
 *
 * @return returns 0 on success
 */
int wolfCLU_printX509PubKey(char* inFile, int inForm, char* outFile,
        int silentFlag);
/* function for processing input/output based on format requests from user */
int wolfCLU_parseFile(char* inFile, int inForm, char* outFile, int outForm,
                                                               int silentFlag);

#endif /* WOLFCLU_PARSE_H */

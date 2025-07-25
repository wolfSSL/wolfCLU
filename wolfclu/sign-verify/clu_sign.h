/* clu_sign.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
    #include <wolfssl/wolfcrypt/asn_public.h>
#endif
#ifdef HAVE_DILITHIUM
    #include <wolfssl/wolfcrypt/dilithium.h>
#endif
#ifdef WOLFSSL_HAVE_XMSS
    #include <wolfssl/wolfcrypt/wc_xmss.h>
#endif

enum {
    RSA_SIG_VER,
    ECC_SIG_VER,
    ED25519_SIG_VER,
    DILITHIUM_SIG_VER,
    XMSS_SIG_VER,
    XMSSMT_SIG_VER,
};

int wolfCLU_sign_data(char*, char*, char*, int, int);


int wolfCLU_sign_data_rsa(byte*, char*, word32, char*, int);
int wolfCLU_sign_data_ecc(byte*, char*, word32, char*, int);
int wolfCLU_sign_data_ed25519(byte*, char*, word32, char*, int);
int wolfCLU_sign_data_dilithium (byte*, char*, word32, char*, int);
int wolfCLU_sign_data_xmss(byte*, char*, int, char*);
int wolfCLU_sign_data_xmssmt(byte*, char*, int, char*);

int wolfCLU_KeyPemToDer(unsigned char** pkeyBuf, int pkeySz, int pubIn);

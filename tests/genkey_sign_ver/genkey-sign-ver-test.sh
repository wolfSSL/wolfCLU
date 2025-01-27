#!/bin/sh

# genkey-sign-ver-test.sh
#
# Copyright (C) 2006-2021 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
#/
#/
#

# Skip test if filesystem disabled
FILESYSTEM=`cat config.log | grep "disable\-filesystem"`
if [ "$FILESYSTEM" != "" ]
then
    exit 77
fi

cleanup_genkey_sign_ver(){
    rm -f ecckey
    rm ecckey.priv
    rm ecckey.pub
    rm edkey.priv
    rm edkey.pub
    rm rsakey.priv
    rm rsakey.pub
    rm mldsakey.priv
    rm mldsakey.pub
    rm ecc-signed.sig
    rm ed-signed.sig
    rm rsa-signed.sig
    rm rsa-sigout.private_result
    rm rsa-sigout.public_result
    rm mldsa-signed.sig
    rm xmss-signed.sig
    # rm xmssmt-signed.sig
    rm sign-this.txt

    # XMSS/XMSS^MT key files
    rm XMSS-SHA2_10_256.priv
    rm XMSS-SHA2_10_256.pub
    # rm XMSS-SHA2_16_256.priv
    # rm XMSS-SHA2_16_256.pub
    # rm XMSS-SHA2_20_256.priv
    # rm XMSS-SHA2_20_256.pub

    # rm XMSSMT-SHA2_20-2_256.priv
    # rm XMSSMT-SHA2_20-2_256.pub
    # rm XMSSMT-SHA2_20-4_256.priv
    # rm XMSSMT-SHA2_20-4_256.pub
    # rm XMSSMT-SHA2_40-2_256.priv
    # rm XMSSMT-SHA2_40-2_256.pub
    # rm XMSSMT-SHA2_40-4_256.priv
    # rm XMSSMT-SHA2_40-4_256.pub
    # rm XMSSMT-SHA2_40-8_256.priv
    # rm XMSSMT-SHA2_40-8_256.pub
    # rm XMSSMT-SHA2_60-3_256.priv
    # rm XMSSMT-SHA2_60-3_256.pub
    # rm XMSSMT-SHA2_60-6_256.priv
    # rm XMSSMT-SHA2_60-6_256.pub
    # rm XMSSMT-SHA2_60-12_256.priv
    # rm XMSSMT-SHA2_60-12_256.pub
}
trap cleanup_genkey_sign_ver INT TERM EXIT

create_sign_data_file(){
    printf '%s\n' "Sign this data" > sign-this.txt
}

rsa_compare_decrypted(){
    if [ "${1}" = "${2}" ]; then
        printf '%s\n' "Decrypted matches original, success!"
        printf '%s\n' "DECRYPTED --> ${1}"
        printf '%s\n' "ORIGINAL --> ${2}"
    else
        printf '%s\n' "Decrypted mismatch with original, FAILURE!"
        printf '%s\n' "DECRYPTED --> ${1}"
        printf '%s\n' "ORIGINAL --> ${2}" && exit -1
    fi
}

gen_key_sign_ver_test(){

    # generate a key pair for signing
    if [ $1 = "dilithium" ]; then
        ./wolfssl -genkey $1 -level $5 -out $2 -outform $4 -output KEYPAIR
    elif [ $1 = "xmss" ]; then
        ./wolfssl -genkey $1 -height $5 -out $2 -outform $4 -output KEYPAIR
    elif [ $1 = "xmssmt" ]; then
        ./wolfssl -genkey $1 -height $5 -layer $6 -out $2 -outform $4 -output KEYPAIR
    else
        ./wolfssl -genkey $1 -out $2 -outform $4 KEYPAIR
    fi
    RESULT=$?
    printf '%s\n' "genkey RESULT - $RESULT"
    [ $RESULT -ne 0 ] && printf '%s\n' "Failed $1 genkey" && \
    printf '%s\n' "Before running this test please configure wolfssl with" && \
    printf '%s\n' "--enable-keygen" && exit -1

    # test signing with priv key
    ./wolfssl -$1 -sign -inkey $2.priv -inform $4 -in sign-this.txt -out $3
    RESULT=$?
    printf '%s\n' "sign RESULT - $RESULT"
    [ $RESULT -ne 0 ] && printf '%s\n' "Failed $1 sign" && exit -1

    # test verifying with priv key
    if [ "${1}" = "rsa" ]; then
        ./wolfssl -$1 -verify -inkey $2.priv -inform $4 -sigfile $3 -in sign-this.txt \
                  -out $5.private_result
    elif [ "${1}" = "dilithium" ] || [ "${1}" = "xmss" ] || [ "${1}" = "xmssmt" ]; then
        # ./wolfssl -$1 -verify -inkey $2.priv -inform $4 -sigfile $3 -in sign-this.txt
        # pass
        :
    else
        ./wolfssl -$1 -verify -inkey $2.priv -inform $4 -sigfile $3 -in sign-this.txt
    fi
    RESULT=$?
    printf '%s\n' "private verify RESULT - $RESULT"
    [ $RESULT -ne 0 ] && printf '%s\n' "Failed $1 private verify" && exit -1

    # test verifying with pub key
    if [ "${1}" = "rsa" ]; then
        ./wolfssl -$1 -verify -inkey $2.pub -inform $4 -sigfile $3 -in sign-this.txt \
                  -out $5.public_result -pubin
    else
        ./wolfssl -$1 -verify -inkey $2.pub -inform $4 -sigfile $3 -in sign-this.txt -pubin
    fi
    RESULT=$?
    printf '%s\n' "public verify RESULT - $RESULT"
    [ $RESULT -ne 0 ] && printf '%s\n' "Failed $1 public verify " && exit -1

    if [ $1 = "rsa" ]; then
        ORIGINAL=`cat -A sign-this.txt`

        DECRYPTED=`cat -A $5.private_result`
        rsa_compare_decrypted "${DECRYPTED}" "${ORIGINAL}"

        DECRYPTED=`cat -A $5.public_result`
        rsa_compare_decrypted "${DECRYPTED}" "${ORIGINAL}"
    fi

}

create_sign_data_file

ALGORITHM="ed25519"
KEYFILENAME="edkey"
SIGOUTNAME="ed-signed.sig"
DERPEMRAW="der"
gen_key_sign_ver_test ${ALGORITHM} ${KEYFILENAME} ${SIGOUTNAME} ${DERPEMRAW}

ALGORITHM="ecc"
KEYFILENAME="ecckey"
SIGOUTNAME="ecc-signed.sig"
DERPEMRAW="der"
gen_key_sign_ver_test ${ALGORITHM} ${KEYFILENAME} ${SIGOUTNAME} ${DERPEMRAW}

ALGORITHM="rsa"
KEYFILENAME="rsakey"
SIGOUTNAME="rsa-signed.sig"
DERPEMRAW="der"
VERIFYOUTNAME="rsa-sigout"
gen_key_sign_ver_test ${ALGORITHM} ${KEYFILENAME} ${SIGOUTNAME} ${DERPEMRAW} ${VERIFYOUTNAME}

ALGORITHM="ed25519"
KEYFILENAME="edkey"
SIGOUTNAME="ed-signed.sig"
DERPEMRAW="pem"
gen_key_sign_ver_test ${ALGORITHM} ${KEYFILENAME} ${SIGOUTNAME} ${DERPEMRAW}

ALGORITHM="ecc"
KEYFILENAME="ecckey"
SIGOUTNAME="ecc-signed.sig"
DERPEMRAW="pem"
gen_key_sign_ver_test ${ALGORITHM} ${KEYFILENAME} ${SIGOUTNAME} ${DERPEMRAW}

ALGORITHM="rsa"
KEYFILENAME="rsakey"
SIGOUTNAME="rsa-signed.sig"
DERPEMRAW="pem"
VERIFYOUTNAME="rsa-sigout"
gen_key_sign_ver_test ${ALGORITHM} ${KEYFILENAME} ${SIGOUTNAME} ${DERPEMRAW} ${VERIFYOUTNAME}

ALGORITHM="ed25519"
KEYFILENAME="edkey"
SIGOUTNAME="ed-signed.sig"
DERPEMRAW="raw"
gen_key_sign_ver_test ${ALGORITHM} ${KEYFILENAME} ${SIGOUTNAME} ${DERPEMRAW}

if ./wolfssl -genkey -h 2>&1 | grep -A6 "Available keys with current configure" | grep dilithium; then
    ALGORITHM="dilithium"
    KEYFILENAME="mldsakey"
    SIGOUTNAME="mldsa-signed.sig"
    DERPEMRAW="der"
    for level in 2 3 5
    do
        gen_key_sign_ver_test ${ALGORITHM} ${KEYFILENAME} ${SIGOUTNAME} ${DERPEMRAW} ${level}
    done

ALGORITHM="dilithium"
KEYFILENAME="mldsakey"
SIGOUTNAME="mldsa-signed.sig"
DERPEMRAW="pem"
for level in 2 3 5
do
    gen_key_sign_ver_test ${ALGORITHM} ${KEYFILENAME} ${SIGOUTNAME} ${DERPEMRAW} ${level}
done
fi

# Check if xmss is availabe
if ./wolfssl xmss -help 2>&1 | grep -A6 "Available keys with current configure" | grep xmss; then
    printf "Testing XMSS sign/verify\n"
    ALGORITHM="xmss"
    SIGOUTNAME="xmss-signed.sig"
    DERPEMRAW="raw"
    HEIGHT=10

    gen_key_sign_ver_test ${ALGORITHM} "XMSS-SHA2_${HEIGHT}_256" ${SIGOUTNAME} ${DERPEMRAW} ${HEIGHT}

    # Too long to run
    # for HEIGHT in 10 16 20
    # do
    #     KEYFILENAME="XMSS-SHA2_${HEIGHT}_256"
    #     gen_key_sign_ver_test ${ALGORITHM} ${KEYFILENAME} ${SIGOUTNAME} ${DERPEMRAW} ${HEIGHT}
    # done

    # ALGORITHM="xmssmt"
    # SIGOUTNAME="xmssmt-signed.sig"
    # DERPEMRAW="raw"
    # HEIGHT=20

    # for LAYER in 2 4
    # do
    #     KEYFILENAME="XMSSMT-SHA2_${HEIGHT}-${LAYER}_256"
    #     gen_key_sign_ver_test ${ALGORITHM} ${KEYFILENAME} ${SIGOUTNAME} ${DERPEMRAW} ${HEIGHT} ${LAYER}
    # done

    # ALGORITHM="xmssmt"
    # SIGOUTNAME="xmssmt-signed.sig"
    # DERPEMRAW="raw"
    # HEIGHT=40

    # for LAYER in 2 4 8
    # do
    #     KEYFILENAME="XMSSMT-SHA2_${HEIGHT}-${LAYER}_256"
    #     gen_key_sign_ver_test ${ALGORITHM} ${KEYFILENAME} ${SIGOUTNAME} ${DERPEMRAW} ${HEIGHT} ${LAYER}
    # done

    # ALGORITHM="xmssmt"
    # SIGOUTNAME="xmssmt-signed.sig"
    # DERPEMRAW="raw"
    # HEIGHT=60

    # for LAYER in 3 6 12
    # do
    #     KEYFILENAME="XMSSMT-SHA2_${HEIGHT}-${LAYER}_256"
    #     gen_key_sign_ver_test ${ALGORITHM} ${KEYFILENAME} ${SIGOUTNAME} ${DERPEMRAW} ${HEIGHT} ${LAYER}
    # done
fi


exit 0

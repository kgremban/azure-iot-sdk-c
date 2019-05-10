// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

static void initialize_library(void)
{
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
}

static int generate_ecc_keypair(EC_KEY** ecc_curve_key)
{
    int result;

    if ((*ecc_curve_key = EC_KEY_new_by_curve_name(OBJ_txt2nid("secp521r1"))) == NULL)
    {
        printf("EC Key curve name failed\r\n");
        result = __LINE__;
    }
    else
    {
        // For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag
        EC_KEY_set_asn1_flag(*ecc_curve_key, OPENSSL_EC_NAMED_CURVE);

        if (EC_KEY_generate_key(*ecc_curve_key) == 0)
        {
            EC_KEY_free(*ecc_curve_key);
            printf("Failure generating ECC Key\r\n");
            result = __LINE__;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

static int show_key_info(EC_KEY* ecc_curve_key)
{
    int result;
    EVP_PKEY* pkey;
    BIO* output_bio;

    if ((output_bio = BIO_new(BIO_s_file())) == NULL)
    {
        printf("Failure creating bio\r\n");
        result = __LINE__;
    }
    else if ((pkey = EVP_PKEY_new()) == NULL)
    {
        printf("Failure generating EVP_PKEY\r\n");
        result = __LINE__;
        BIO_free_all(output_bio);
    }
    else
    {
        output_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

        if ((EVP_PKEY_assign_EC_KEY(pkey, ecc_curve_key)) == 0)
        {
            printf("Failure assigning EVP_PKEY\r\n");
            result = __LINE__;
        }
        else
        {
            if (!PEM_write_bio_PrivateKey(output_bio, pkey, NULL, NULL, 0, 0, NULL))
            {
                printf("Error writing private key data in PEM format\r\n");
            }
            else if(!PEM_write_bio_PUBKEY(output_bio, pkey))
            {
                printf("Error writing public key data in PEM format");
            }
        }
        BIO_free_all(output_bio);
        EVP_PKEY_free(pkey);
    }
    return result;
}

int main()
{
    int result;
    initialize_library();

    EC_KEY* ecc_curve_key;
    if (generate_ecc_keypair(&ecc_curve_key) != 0)
    {
        printf("Failure generating ECC Keys\r\n");
        result = __LINE__;
    }
    else
    {
        show_key_info(ecc_curve_key);
        EC_KEY_free(ecc_curve_key);
    }

    (void)printf("\r\nPress any key to continue:\r\n");
    (void)getchar();
    return result;
}
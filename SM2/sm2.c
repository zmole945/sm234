// \file:sm2.c
//SM2 Algorithm
//2011-11-10
//author:goldboar
//email:goldboar@163.com
//depending:opnessl library

//SM2 Standards: http://www.oscca.gov.cn/News/201012/News_1197.htm

#include <limits.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include "kdf.h"

#define  NID_X9_62_prime_field 406
static void BNPrintf(BIGNUM* bn)
{
    char *p=NULL;
    p=BN_bn2hex(bn);
    printf("%s",p);
    OPENSSL_free(p);
}

ECDSA_SIG *sm2_do_sign(
        const unsigned char *dgst,
        int                 dgst_len,
        const BIGNUM        *r,
        const BIGNUM        *rGx,
        EC_KEY              *eckey)
{
    int         ok = 0;
    int         i;
    ECDSA_SIG   *ret;
    BN_CTX      *ctx = NULL;
    EC_GROUP    *group;

    BIGNUM      *sigs, *m=NULL,*tmp=NULL,*n=NULL;
    BIGNUM      *k;
    BIGNUM      *sigr,*one=NULL;

    group   = EC_KEY_get0_group(eckey);
    k       = EC_KEY_get0_private_key(eckey);

    if (group == NULL || k == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ret = ECDSA_SIG_new();
    if (!ret) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    sigs = ret->s;
    sigr = ret->r;

    if (    (ctx = BN_CTX_new()) == NULL ||
            (n = BN_new()) == NULL ||
            (tmp = BN_new()) == NULL ||
            (m = BN_new()) == NULL || 
            (one = BN_new()) == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_GROUP_get_order(group, n, ctx)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
        goto err;
    }

    i = BN_num_bits(n);
    if (8 * dgst_len > i) dgst_len = (i + 7)/8;
    if (!BN_bin2bn(dgst, dgst_len, m)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        goto err;
    }
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7))) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        goto err;
    }

    do {
        //sigr=(e+x1) mod n ----- sigr = (m+rGx) mod n
        if (!BN_mod_add_quick(sigr, m, rGx, n)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        printf("=================\n");
        printf("sigr = (m+rGx) mod n\n");
        printf("m   = ");
        BNPrintf(m);
        printf("\n");
        printf("rGx = ");
        BNPrintf(rGx);
        printf("\n");
        printf("n   = ");
        BNPrintf(n);
        printf("\n");
        printf("sigr= ");
        BNPrintf(sigr);
        printf("\n");

        if(BN_is_zero(sigr)) continue;

#if 1
        //tmp = sigr + r
        printf("=================\n");
        printf("tmp = sigr + r\n");
        BN_add(tmp, sigr, r);
        printf("tmp = ");
        BNPrintf(tmp);
        printf("\n");
        if(BN_ucmp(tmp, n) == 0) continue;
#endif

        //tmp = k*sigr mod n
        if (!BN_mod_mul(tmp, k, sigr, n, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        printf("=================\n");
        printf("tmp = k*sigr mod n\n");
        printf("k   = ");
        BNPrintf(k);
        printf("\n");
        printf("sigr= ");
        BNPrintf(sigr);
        printf("\n");
        printf("n   = ");
        BNPrintf(n);
        printf("\n");
        printf("tmp = ");
        BNPrintf(tmp);
        printf("\n");

        //sigs = (r - tmp) mod n
        if (!BN_mod_sub_quick(sigs, r, tmp, n)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        printf("=================\n");
        printf("sigs = (r - tmp) mod n\n");
        printf("r   = ");
        BNPrintf(r);
        printf("\n");
        printf("tmp = ");
        BNPrintf(tmp);
        printf("\n");
        printf("n   = ");
        BNPrintf(n);
        printf("\n");
        printf("sigs= ");
        BNPrintf(sigs);
        printf("\n");

        // tmp = (k+1) mod n
        BN_one(one);
        if (!BN_mod_add_quick(tmp, k, one, n)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        printf("=================\n");
        printf("tmp = (k+1) mod n\n");
        printf("k   = ");
        BNPrintf(k);
        printf("\n");
        printf("one = ");
        BNPrintf(one);
        printf("\n");
        printf("n   = ");
        BNPrintf(n);
        printf("\n");
        printf("tmp = ");
        BNPrintf(tmp);
        printf("\n");

        //tmp = 1/tmp mod n
        if (!BN_mod_inverse(tmp, tmp, n, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
            goto err;	
        }
        printf("=================\n");
        printf("tmp = 1/tmp mod n\n");
        printf("n   = ");
        BNPrintf(n);
        printf("\n");
        printf("tmp = ");
        BNPrintf(tmp);
        printf("\n");

        //sigs = sigs*tmp mod n
        if (!BN_mod_mul(sigs, sigs, tmp, n, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        printf("=================\n");
        printf("sigs = sigs*tmp mod n\n");
        printf("tmp = ");
        BNPrintf(tmp);
        printf("\n");
        printf("n   = ");
        BNPrintf(n);
        printf("\n");
        printf("sigs= ");
        BNPrintf(sigs);
        printf("\n");


        if (BN_is_zero(sigs)) {
            /* if k and r have been supplied by the caller
             * don't to generate new k and r values */
            if (r != NULL && rGx != NULL) {
                ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ECDSA_R_NEED_NEW_SETUP_VALUES);
                goto err;
            }
        } else {
            BN_rand(tmp, 256, 0xffffffff, 0);

            /* sigs != 0 => we have a valid signature */
            break;
        }
    }
    while (1);

    ok = 1;
err:
    if (!ok) {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }
    if (ctx) BN_CTX_free(ctx);
    if (m) BN_clear_free(m);
    if (tmp) BN_clear_free(tmp);
    if (n) BN_free(n);
    if (rGx) BN_clear_free(rGx);
    if (one) BN_clear_free(one);
    return ret;
}

int sm2_do_verify(
        const unsigned char *dgst,
        int                 dgst_len,
        const ECDSA_SIG     *sig,
        EC_KEY              *eckey)
{
    int ret = -1, i;
    BN_CTX   *ctx;
    BIGNUM   *order, *R,  *m, *X,*t;
    EC_POINT *point = NULL;
    const EC_GROUP *group;
    const EC_POINT *pub_key;

    /* check input values */
    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL ||
            (pub_key = EC_KEY_get0_public_key(eckey)) == NULL || sig == NULL)
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ECDSA_R_MISSING_PARAMETERS);
        return -1;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        return -1;
    }
    BN_CTX_start(ctx);
    order   = BN_CTX_get(ctx);	
    R       = BN_CTX_get(ctx);
    t       = BN_CTX_get(ctx);
    m       = BN_CTX_get(ctx);
    X       = BN_CTX_get(ctx);
    if (!X)
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, ctx))
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
        goto err;
    }

    if (BN_is_zero(sig->r)          || BN_is_negative(sig->r) || 
            BN_ucmp(sig->r, order) >= 0 || BN_is_zero(sig->s)  ||
            BN_is_negative(sig->s)      || BN_ucmp(sig->s, order) >= 0)
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ECDSA_R_BAD_SIGNATURE);

        ret = 0;	/* signature is invalid */
        goto err;
    }

    //t =(r+s) mod n
    if (!BN_mod_add_quick(t, sig->s, sig->r,order))
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }
    if (BN_is_zero(t))
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ECDSA_R_BAD_SIGNATURE);

        ret = 0;	/* signature is invalid */
        goto err;
    }

    //point = s*G+t*PA
    if ((point = EC_POINT_new(group)) == NULL)
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!EC_POINT_mul(group, point, sig->s, pub_key, t, ctx))
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
        goto err;
    }
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
    {
        if (!EC_POINT_get_affine_coordinates_GFp(group,
                    point, X, NULL, ctx))
        {
            ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
            goto err;
        }
    }
    else /* NID_X9_62_characteristic_two_field */
    {
        if (!EC_POINT_get_affine_coordinates_GF2m(group,
                    point, X, NULL, ctx))
        {
            ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
            goto err;
        }
    }

    i = BN_num_bits(order);
    /* Need to truncate digest if it is too long: first truncate whole
     * bytes.
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7)/8;
    if (!BN_bin2bn(dgst, dgst_len, m))
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }
    /* If still too long truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7)))
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }

    /* R = m + X mod order */
    if (!BN_mod_add_quick(R, m, X, order))
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }

    /*  if the signature is correct R is equal to sig->r */
    ret = (BN_ucmp(R, sig->r) == 0);
err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    if (point)
        EC_POINT_free(point);
    return ret;
}


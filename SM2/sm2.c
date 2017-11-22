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


static int sm2_sign_setup(
        EC_KEY *eckey,
        BN_CTX *ctx_in,
        BIGNUM **kp,
        BIGNUM **rp)
{
    BN_CTX      *ctx = NULL;
    BIGNUM	*k = NULL, *r = NULL, *order = NULL, *X = NULL;
    EC_POINT *tmp_point=NULL;
    const EC_GROUP *group;
    int 	 ret = 0;

    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL)
    {
        ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (ctx_in == NULL) 
    {
        if ((ctx = BN_CTX_new()) == NULL)
        {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP,ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    else
        ctx = ctx_in;

    k     = BN_new();	/* this value is later returned in *kp */
    r     = BN_new();	/* this value is later returned in *rp */
    order = BN_new();
    X     = BN_new();
    if (!k || !r || !order || !X)
    {
        ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if ((tmp_point = EC_POINT_new(group)) == NULL)
    {
        ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
        goto err;
    }
    if (!EC_GROUP_get_order(group, order, ctx))
    {
        ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
        goto err;
    }

    do
    {
        /* get random k */	
        do
            if (!BN_rand_range(k, order))
            {
                ECDSAerr(
                        ECDSA_F_ECDSA_SIGN_SETUP,
                        ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED);	
                goto err;
            }
        while (BN_is_zero(k));

        /* compute r the x-coordinate of generator * k */
        if (!EC_POINT_mul(
                    group,
                    tmp_point,
                    k,
                    NULL,
                    NULL,
                    ctx))
        {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
            goto err;
        }
        if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) 
                == NID_X9_62_prime_field)
        {
            if (!EC_POINT_get_affine_coordinates_GFp(
                        group,
                        tmp_point, 
                        X, 
                        NULL,
                        ctx))
            {
                ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP,ERR_R_EC_LIB);
                goto err;
            }
        }
        else /* NID_X9_62_characteristic_two_field */
        {
            if (!EC_POINT_get_affine_coordinates_GF2m(
                        group,
                        tmp_point,
                        X,
                        NULL,
                        ctx))
            {
                ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP,ERR_R_EC_LIB);
                goto err;
            }
        }
        if (!BN_nnmod(r, X, order, ctx))
        {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
            goto err;
        }
    }
    while (BN_is_zero(r));

    /* compute the inverse of k */
    // 	if (!BN_mod_inverse(k, k, order, ctx))
    // 	{
    // 		ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
    // 		goto err;	
    // 	}
    /* clear old values if necessary */
    if (*rp != NULL)
        BN_clear_free(*rp);
    if (*kp != NULL) 
        BN_clear_free(*kp);
    /* save the pre-computed values  */
    *rp = r;
    *kp = k;
    ret = 1;
err:
    if (!ret)
    {
        if (k != NULL) BN_clear_free(k);
        if (r != NULL) BN_clear_free(r);
    }
    if (ctx_in == NULL) 
        BN_CTX_free(ctx);
    if (order != NULL)
        BN_free(order);
    if (tmp_point != NULL) 
        EC_POINT_free(tmp_point);
    if (X)
        BN_clear_free(X);
    return(ret);
}


ECDSA_SIG *sm2_do_sign(
        const unsigned char *dgst,
        int                 dgst_len,
        const BIGNUM        *in_k,
        const BIGNUM        *in_r,
        EC_KEY              *eckey)
{
    int             ok = 0, i;
    BIGNUM          *k=NULL, *s, *m=NULL,*tmp=NULL,*order=NULL;
    const BIGNUM    *ck;
    BN_CTX          *ctx = NULL;
    const EC_GROUP  *group;
    ECDSA_SIG       *ret;

    //ECDSA_DATA *ecdsa;
    const BIGNUM    *priv_key;
    BIGNUM          *r,*x=NULL,*a=NULL;	//new added

    //ecdsa    = ecdsa_check(eckey);
    group    = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);

    if (group == NULL || priv_key == NULL /*|| ecdsa == NULL*/)
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ret = ECDSA_SIG_new();
    if (!ret)
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    s = ret->s;
    r = ret->r;

    if ((ctx = BN_CTX_new()) == NULL ||
        (order = BN_new()) == NULL ||
        (tmp = BN_new()) == NULL ||
        (m = BN_new()) == NULL || 
        (x = BN_new()) == NULL ||
        (a = BN_new()) == NULL)
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, ctx))
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
        goto err;
    }

    i = BN_num_bits(order);

    /* Need to truncate digest if it is too long: first truncate whole
     * bytes.
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7)/8;
    if (!BN_bin2bn(dgst, dgst_len, m))
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        goto err;
    }
    /* If still too long truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7)))
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        goto err;
    }

    do
    {
        if (in_k == NULL || in_r == NULL)
        {
            if (!sm2_sign_setup(eckey, ctx, &k, &x))
            {
                ECDSAerr(ECDSA_F_ECDSA_DO_SIGN,ERR_R_ECDSA_LIB);
                goto err;
            }
            ck = k;
        }
        else
        {
            ck  = in_k;
            if (BN_copy(x, in_r) == NULL)
            {
                ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }

        //r=(e+x1) mod n
        if (!BN_mod_add_quick(r, m, x, order))
        {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
            goto err;
        }

        if(BN_is_zero(r) )
            continue;

        BN_add(tmp, r, ck);
        if(BN_ucmp(tmp,order) == 0)
            continue;

        if (!BN_mod_mul(tmp, priv_key, r, order, ctx))
        {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
            goto err;
        }

        if (!BN_mod_sub_quick(s, ck, tmp, order))
        {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        BN_one(a);

        if (!BN_mod_add_quick(tmp, priv_key, a, order))
        {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        /* compute the inverse of 1+dA */
        if (!BN_mod_inverse(tmp, tmp, order, ctx))
        {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
            goto err;	
        }

        if (!BN_mod_mul(s, s, tmp, order, ctx))
        {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
            goto err;
        }

        if (BN_is_zero(s))
        {
            /* if k and r have been supplied by the caller
             * don't to generate new k and r values */
            if (in_k != NULL && in_r != NULL)
            {
                ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ECDSA_R_NEED_NEW_SETUP_VALUES);
                goto err;
            }
        }
        else {
            BN_rand(tmp, 256, 0xffffffff, 0);

            /* s != 0 => we have a valid signature */
            break;
        }
    }
    while (1);

    ok = 1;
err:
    if (!ok)
    {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }
    if (ctx)
        BN_CTX_free(ctx);
    if (m)
        BN_clear_free(m);
    if (tmp)
        BN_clear_free(tmp);
    if (order)
        BN_free(order);
    if (k)
        BN_clear_free(k);
    if (x)
        BN_clear_free(x);
    if (a)
        BN_clear_free(a);
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include "sm2.h"

#ifdef win32
#pragma comment(lib,"libeay32.lib")
#endif

#define ABORT do { \
    fflush(stdout); \
    fprintf(stderr, "%s:%d: ABORT\n", __FILE__, __LINE__); \
    ERR_print_errors_fp(stderr); \
    exit(1); \
} while (0)

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

void BNPrintf(BIGNUM* bn)
{
    char *p=NULL;
    p=BN_bn2hex(bn);
    printf("%s",p);
    OPENSSL_free(p);
}


int SM2_Test_Vecotor3()
{
#if 1
#define SM2_P  ("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF")
#define SM2_A  ("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC")
#define SM2_B  ("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93")
#define SM2_N  ("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123")
#define SM2_GX ("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7")
#define SM2_GY ("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0")
#define SM2_PRIV ("094CC2FDB6663C76F17CA75EA9047DEB6B79E0CD31E9979A3A8D4A5B069AD10F")
#define SM2_PUBX ("D86F332E496D859856E563C3A4E5566813AF0A8C77487264ABE76FA2364D787B")
#define SM2_PUBY ("C7F9081B66337195B475446392B98EE82838E9A6AD544F0C5207DFFE4D8395DA")
#define SM2_RAND ("E6930C9DF94913EAC5BB496FBFC65A2A3F3BF771248E0B5E1C55BA22F08B31D6")
#define SM2_SIGR ("2E1091A7E563411C029D10135DBAA5C5D2B80C2EF6840693E55EE2072D7FDBE1")
#define SM2_SIGS ("D6DA45992C86CB869D6DB181465ADADD89CF40DD31FD547FA104909F30D4D41B")
#else
#define SM2_P  ("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3")
#define SM2_A  ("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498")
#define SM2_B  ("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A")
#define SM2_N  ("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7")
#define SM2_GX ("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D")
#define SM2_GY ("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2")
#define SM2_PRIV ("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")
#define SM2_PUBX ("0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A")
#define SM2_PUBY ("7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857")
#define SM2_RAND ("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F")
#define SM2_SIGR ("40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1")
#define SM2_SIGS ("6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7")
#endif

    BN_CTX      *ctx = NULL;
    BIGNUM      *p, *a, *b;
    EC_GROUP    *group;
    EC_POINT    *GFp, *PUBp, *RANDp;
    BIGNUM      *gfpx, *gfpy, *n;
    BIGNUM      *randx, *randy, *rand;
    BIGNUM      *priv, *pubx, *puby;
    EC_KEY	*eckey = NULL;

    unsigned char	*signature, *signature_tmp;

    int	sig_len;
    int i;

    int ret;

    unsigned char	digest[32] = {
        0x54, 0x90, 0xfc, 0x4d, 0xf4, 0x6a, 0xa3, 0x3f,
        0xc0, 0x8b, 0x40, 0x31, 0x6d, 0x2d, 0x5d, 0x1f,
        0x42, 0x66, 0xfb, 0xf5, 0x62, 0xb8, 0x08, 0xca,
        0x68, 0x51, 0xf6, 0xb0, 0x21, 0x78, 0x50, 0x75};

    BIGNUM *kinv, *rp,*order; 

    ECDSA_SIG *ecsig = NULL;

    printf("================================================\n");
    printf("set curve\n");
    ctx = BN_CTX_new();
    if (!ctx) ABORT;

    p = BN_new();
    a = BN_new();
    b = BN_new();
    if (!p || !a || !b) ABORT;

    group = EC_GROUP_new(EC_GFp_mont_method());
    if (!group) ABORT;

    if (!BN_hex2bn(&p, SM2_P)) ABORT;
    if (!BN_hex2bn(&a, SM2_A)) ABORT;
    if (!BN_hex2bn(&b, SM2_B)) ABORT;

    if (!BN_is_prime_ex(p, BN_prime_checks, ctx, NULL)) ABORT;
    if (!EC_GROUP_set_curve_GFp(group, p, a, b, ctx)) ABORT;
    fprintf(stdout, "p = ");
    BNPrintf(p);
    printf("\n");
    fprintf(stdout, "a = ");
    BNPrintf(a);
    printf("\n");
    fprintf(stdout, "b = ");
    BNPrintf(b);
    printf("\n");
    printf("\n\n\n");

    printf("================================================\n");
    printf("choose n and G\n");
    GFp = EC_POINT_new(group);          //基点
    if (!GFp) ABORT;

    gfpx    = BN_new();
    gfpy    = BN_new();
    n       = BN_new();                 //order
    if (!gfpx || !gfpy || !n) ABORT;

    if (!BN_hex2bn(&gfpx, SM2_GX)) ABORT;
    if (!EC_POINT_set_compressed_coordinates_GFp(
                group,
                GFp, 
                gfpx,
                0,
                ctx)) ABORT;
    if (!EC_POINT_is_on_curve(
                group,
                GFp,
                ctx)) ABORT;
    if (!BN_hex2bn(&n, SM2_N)) ABORT;
    if (!EC_GROUP_set_generator(
                group,
                GFp,
                n,
                BN_value_one())) ABORT;
    if (!EC_POINT_get_affine_coordinates_GFp(
                group,
                GFp,
                gfpx,
                gfpy,
                ctx)) ABORT;
    fprintf(stdout, "n = ");
    BNPrintf(n);
    printf("\n");
    fprintf(stdout, "gfpx = ");
    BNPrintf(gfpx);
    printf("\n");
    fprintf(stdout, "gfpy = ");
    BNPrintf(gfpy);
    printf("\n");
    printf("\n\n\n");

    printf("================================================\n");
    printf("Create key:\n");
    priv = BN_new();
    pubx = BN_new();
    puby = BN_new();
    if (!priv || !pubx || !puby) ABORT;

    PUBp = EC_POINT_new(group);
    if (!PUBp) ABORT;

    if (!BN_hex2bn(&priv, SM2_PRIV)) ABORT;
    if (!EC_POINT_mul(
                group,
                PUBp,
                priv,
                NULL,
                NULL,
                ctx)) ABORT;
    if (!EC_POINT_get_affine_coordinates_GFp(
                group,
                PUBp,
                pubx,
                puby,
                ctx)) ABORT;

    if ((eckey = EC_KEY_new()) == NULL)
        goto builtin_err;
    if (EC_KEY_set_group(eckey, group) == 0)
    {
        fprintf(stdout," failed\n");
        goto builtin_err;
    }

    EC_KEY_set_private_key(eckey, priv);
    EC_KEY_set_public_key(eckey, PUBp);

    /* check key */
    if (!EC_KEY_check_key(eckey))
    {
        fprintf(stdout," failed\n");
        goto builtin_err;
    }

    fprintf(stdout, "priv = ");
    BNPrintf(priv);
    printf("\n");
    fprintf(stdout, "pubx = ");
    BNPrintf(pubx);
    printf("\n");
    fprintf(stdout, "puby = ");
    BNPrintf(puby);
    printf("\n");
    printf("\n\n\n");

    
    printf("================================================\n");
    printf("get r and randG\n");
    rand    = BN_new();
    randx   = BN_new();
    randy   = BN_new();
    if (!randx || !randy || !rand) ABORT;

    RANDp = EC_POINT_new(group);
    if (!RANDp) ABORT;

    if (!BN_hex2bn(&rand, SM2_RAND)) ABORT;
    if (!EC_POINT_mul(group, RANDp, rand, NULL, NULL, ctx))
    {
        fprintf(stdout, " failed\n");
        goto builtin_err;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(group, RANDp, randx, randy, ctx))
    {
        fprintf(stdout, " failed\n");
        goto builtin_err;
    }
    fprintf(stdout, "rand = ");
    BNPrintf(rand);
    printf("\n");
    fprintf(stdout, "randx = ");
    BNPrintf(randx);
    printf("\n");
    fprintf(stdout, "randy = ");
    BNPrintf(randy);
    printf("\n");
    printf("\n\n\n");

    printf("================================================\n");
    printf("Testing sign:\n");
    printf("digest=\n");
    for(i=0; i<32; i++) {
        printf("%02X", digest[i]);
    }
    printf("\n");

    sig_len = ECDSA_size(eckey);
    if ((signature = OPENSSL_malloc(sig_len)) == NULL)
        goto builtin_err;

    ecsig = ECDSA_SIG_new();
    if (!ecsig) ABORT;

    ecsig = sm2_do_sign(digest, 32, rand, randx, eckey);

    fprintf(stdout, "r = ");
    BNPrintf(ecsig->r);
    printf("\n");
    fprintf(stdout, "s = ");
    BNPrintf(ecsig->s);
    printf("\n");
    printf("\n\n\n");

    printf("================================================\n");
    printf("Testing verify:\n");
    ret = sm2_do_verify(digest, 32, ecsig, eckey);

    printf("ret = %d\n", ret);

builtin_err:	
    OPENSSL_free(signature);
    signature = NULL;
    EC_POINT_free(GFp);
    EC_POINT_free(PUBp);
    EC_POINT_free(RANDp);
    EC_KEY_free(eckey);
    eckey = NULL;
    EC_GROUP_free(group);
    BN_CTX_free(ctx);

    return 0;
}

int main()
{
#if 1
    SM2_Test_Vecotor3();
#else
    CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    ERR_load_crypto_strings();
    RAND_seed(rnd_seed, sizeof rnd_seed); 

    SM2_Test_Vecotor3();

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_state(0);
    CRYPTO_mem_leaks_fp(stderr);
#endif
    return 0;
}

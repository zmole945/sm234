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

#if 0
int SM2_Test_Vecotor()
{
	BN_CTX *ctx = NULL;
	BIGNUM *p, *a, *b;
	EC_GROUP *group;
	EC_POINT *P, *Q, *R;
	BIGNUM *x, *y, *z;
	EC_KEY	*eckey = NULL;
	unsigned char	digest[20];
	unsigned char	*signature = NULL; 
	int	sig_len;


	CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	ERR_load_crypto_strings();
	RAND_seed(rnd_seed, sizeof rnd_seed); /* or BN_generate_prime may fail */
	
	ctx = BN_CTX_new();
	if (!ctx) ABORT;

	/* Curve SM2 (Chinese National Algorithm) */
	//http://www.oscca.gov.cn/News/201012/News_1197.htm
	p = BN_new();
	a = BN_new();
	b = BN_new();
	if (!p || !a || !b) ABORT;
	group = EC_GROUP_new(EC_GFp_mont_method()); /* applications should use EC_GROUP_new_curve_GFp
 	                                             * so that the library gets to choose the EC_METHOD */
	if (!group) ABORT;
	
	if (!BN_hex2bn(&p, "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3")) ABORT;
	if (1 != BN_is_prime_ex(p, BN_prime_checks, ctx, NULL)) ABORT;
	if (!BN_hex2bn(&a, "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498")) ABORT;
	if (!BN_hex2bn(&b, "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A")) ABORT;
	if (!EC_GROUP_set_curve_GFp(group, p, a, b, ctx)) ABORT;

	P = EC_POINT_new(group);
	Q = EC_POINT_new(group);
	R = EC_POINT_new(group);
	if (!P || !Q || !R) ABORT;

	x = BN_new();
	y = BN_new();
	z = BN_new();
	if (!x || !y || !z) ABORT;

	// sm2 testing P256 Vetor
	// p£º8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
	// a£º787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
	// b£º63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
	// xG 421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
	// yG 0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
	// n: 8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7

	if (!BN_hex2bn(&x, "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D")) ABORT;
	if (!EC_POINT_set_compressed_coordinates_GFp(group, P, x, 0, ctx)) ABORT;
	if (!EC_POINT_is_on_curve(group, P, ctx)) ABORT;
	if (!BN_hex2bn(&z, "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7")) ABORT;
	if (!EC_GROUP_set_generator(group, P, z, BN_value_one())) ABORT;
	
	if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)) ABORT;
	fprintf(stdout, "\nChinese sm2 algorithm test -- Generator:\n     x = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n     y = 0x");
	BNPrintf( y);
	fprintf(stdout, "\n");
	/* G_y value taken from the standard: */
	if (!BN_hex2bn(&z, "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2")) ABORT;
	if (0 != BN_cmp(y, z)) ABORT;
	
	fprintf(stdout, "verify degree ...");
	if (EC_GROUP_get_degree(group) != 256) ABORT;
	fprintf(stdout, " ok\n");
	
	fprintf(stdout, "verify group order ...");
	fflush(stdout);
	if (!EC_GROUP_get_order(group, z, ctx)) ABORT;
	if (!EC_GROUP_precompute_mult(group, ctx)) ABORT;
	if (!EC_POINT_mul(group, Q, z, NULL, NULL, ctx)) ABORT;
	if (!EC_POINT_is_at_infinity(group, Q)) ABORT;
 	fflush(stdout);
	fprintf(stdout, " ok\n");

	//testing ECDSA for SM2
	/* create new ecdsa key */
	if ((eckey = EC_KEY_new()) == NULL)
		goto builtin_err;
	if (EC_KEY_set_group(eckey, group) == 0)
	{
		fprintf(stdout," failed\n");
		goto builtin_err;
	}
	/* create key */
	if (!EC_KEY_generate_key(eckey))
	{
		fprintf(stdout," failed\n");
		goto builtin_err;
	}
	/* check key */
	if (!EC_KEY_check_key(eckey))
	{
		fprintf(stdout," failed\n");
		goto builtin_err;
	}
	/* create signature */
	sig_len = ECDSA_size(eckey);
	fprintf(stdout,"Siglength is: %d \n",sig_len);
	if (!RAND_pseudo_bytes(digest, 20))
	{
		fprintf(stdout," failed\n");
		goto builtin_err;
	}
	if ((signature = OPENSSL_malloc(sig_len)) == NULL)
		goto builtin_err;
	if (!SM2_sign(0, digest, 20, signature, &sig_len, eckey))
	{
		fprintf(stdout, " failed\n");
		goto builtin_err;
	}
	fprintf(stdout, "ECSign OK\n");
	/* verify signature */
	if (SM2_verify(0, digest, 20, signature, sig_len, eckey) != 1)
	{
		fprintf(stdout, " failed\n");
		goto builtin_err;
	}
	fprintf(stdout, "ECVerify OK\n");
	/* cleanup */
	OPENSSL_free(signature);
	signature = NULL;
	EC_KEY_free(eckey);
	eckey = NULL;
	
builtin_err:	
	
	EC_POINT_free(P);
	EC_POINT_free(Q);
	EC_POINT_free(R);
	EC_GROUP_free(group);
	BN_CTX_free(ctx);
	return 0;

}
#endif

int SM2_Test_Vecotor2()
{
	BN_CTX *ctx = NULL;
	BIGNUM *p, *a, *b;
	EC_GROUP *group;
	EC_POINT *P, *Q, *R;
	BIGNUM *x, *y, *z;
	EC_KEY	*eckey = NULL;
	unsigned char	*signature, *signature_tmp;
#if 1
	unsigned char	digest[32] = {
            0xB5, 0x24, 0xF5, 0x52,
            0xCD, 0x82, 0xB8, 0xB0,
            0x28, 0x47, 0x6E, 0x00,
            0x5C, 0x37, 0x7F, 0xB1,
            0x9A, 0x87, 0xE6, 0xFC,
            0x68, 0x2D, 0x48, 0xBB,
            0x5D, 0x42, 0xE3, 0xD9,
            0xB9, 0xEF, 0xFE, 0x76};
#else
        //B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76
	unsigned char	digest[32] = "\xB5\x24\xF5\x52\xCD\x82\xB8\xB0\x28\x47\x6E\x00\x5C\x37\x7F\xB1\x9A\x87\xE6\xFC\x68\x2D\x48\xBB\x5D\x42\xE3\xD9\xB9\xEF\xFE\x76"; 
#endif
	int	sig_len;
	BIGNUM *kinv, *rp,*order; 
	ECDSA_SIG *ecsig = ECDSA_SIG_new();
	EC_POINT * DHPoint = NULL;
// 	unsigned char *in="123456";
// 	size_t inlen = 6;
 	size_t outlen = 256;
	unsigned char outkey[256];
	size_t keylen = 256;

	size_t i;

	CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	ERR_load_crypto_strings();
	RAND_seed(rnd_seed, sizeof rnd_seed); /* or BN_generate_prime may fail */
	
	ctx = BN_CTX_new();
	if (!ctx) ABORT;

	/* Curve SM2 (Chinese National Algorithm) */
	//http://www.oscca.gov.cn/News/201012/News_1197.htm
	p = BN_new();
	a = BN_new();
	b = BN_new();
	if (!p || !a || !b) ABORT;
	group = EC_GROUP_new(EC_GFp_mont_method()); /* applications should use EC_GROUP_new_curve_GFp
 	                                             * so that the library gets to choose the EC_METHOD */
	if (!group) ABORT;
	
        printf("================================================\n");
        printf("set curve GFp\n");
	if (!BN_hex2bn(&p, "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3")) ABORT;
	if (1 != BN_is_prime_ex(p, BN_prime_checks, ctx, NULL)) ABORT;
	if (!BN_hex2bn(&a, "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498")) ABORT;
	if (!BN_hex2bn(&b, "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A")) ABORT;
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
        printf("Chinese sm2 algorithm test -- Generator:\n");
	P = EC_POINT_new(group);
	Q = EC_POINT_new(group);
	R = EC_POINT_new(group);
	if (!P || !Q || !R) ABORT;

	x = BN_new();
	y = BN_new();
	z = BN_new();
	if (!x || !y || !z) ABORT;

	// sm2 testing P256 Vetor
	// p£º8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
	// a£º787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
	// b£º63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
	// xG 421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
	// yG 0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
	// n: 8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7

	if (!BN_hex2bn(&x, "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D")) ABORT;
	if (!EC_POINT_set_compressed_coordinates_GFp(group, P, x, 0, ctx)) ABORT;
#if 1
	if (!EC_POINT_is_on_curve(group, P, ctx)) ABORT;

	if (!BN_hex2bn(&z, "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7")) ABORT;
	if (!EC_GROUP_set_generator(group, P, z, BN_value_one())) ABORT;
#endif
	
	if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)) ABORT;
	fprintf(stdout, "n = ");
	BNPrintf(z);
        printf("\n");
	fprintf(stdout, "x = ");
	BNPrintf(x);
        printf("\n");
	fprintf(stdout, "y = ");
	BNPrintf(y);
        printf("\n");
        printf("\n\n\n");

#if 0
        printf("================================================\n");
        printf("Verify EC:\n");
	/* G_y value taken from the standard: */
	if (!BN_hex2bn(&z, "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2")) ABORT;
        printf("standard y:");
	BNPrintf(z);
        printf("\n");
	if (0 != BN_cmp(y, z)) ABORT;
#endif
	
#if 0
	fprintf(stdout, "verify degree ...");
	if (EC_GROUP_get_degree(group) != 256) ABORT;
	fprintf(stdout, " ok\n");
	
	fprintf(stdout, "verify group order ...");
	fflush(stdout);
	if (!EC_GROUP_get_order(group, z, ctx)) ABORT;
	if (!EC_GROUP_precompute_mult(group, ctx)) ABORT;
	if (!EC_POINT_mul(group, Q, z, NULL, NULL, ctx)) ABORT;
	if (!EC_POINT_is_at_infinity(group, Q)) ABORT;
 	fflush(stdout);
	fprintf(stdout, " ok\n");
        printf("\n\n\n");
#endif

        printf("================================================\n");
        printf("Create key:\n");

	//testing ECDSA for SM2
	/* create new ecdsa key */
	if ((eckey = EC_KEY_new()) == NULL)
		goto builtin_err;
	if (EC_KEY_set_group(eckey, group) == 0)
	{
		fprintf(stdout," failed\n");
		goto builtin_err;
	}

	/* create key */
	if (!BN_hex2bn(&z, "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")) ABORT;
	if (!EC_POINT_mul(group,P, z, NULL, NULL, ctx)) ABORT;
	if (!EC_POINT_get_affine_coordinates_GFp(group,P, x, y, ctx)) ABORT;
	fprintf(stdout, "priv = ");
	BNPrintf(z);
        printf("\n");
	fprintf(stdout, "pubx = ");
	BNPrintf(x);
        printf("\n");
	fprintf(stdout, "puby = ");
	BNPrintf(y);
        printf("\n");
        printf("\n\n\n");

	EC_KEY_set_private_key(eckey, z);
	EC_KEY_set_public_key(eckey, P);

	/* check key */
	if (!EC_KEY_check_key(eckey))
	{
		fprintf(stdout," failed\n");
		goto builtin_err;
	}

///////////////////////////////////////////////////////////////////
        printf("================================================\n");
        printf("Testing K Point:\n");
	/* create signature */
	sig_len = ECDSA_size(eckey);
 	//fprintf(stdout,"Siglength is: %d \n",sig_len);
	if ((signature = OPENSSL_malloc(sig_len)) == NULL)
		goto builtin_err;

	rp    = BN_new();
	kinv  = BN_new();
	order = BN_new();

	if (!BN_hex2bn(&z, "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F")) ABORT;
	if (!EC_POINT_mul(group, Q, z, NULL, NULL, ctx))
	{
		fprintf(stdout, " failed\n");
		goto builtin_err;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group,Q, x, y, ctx))
	{
		fprintf(stdout, " failed\n");
		goto builtin_err;
	}
	fprintf(stdout, "z = ");
	BNPrintf(z);
        printf("\n");
	fprintf(stdout, "x = ");
	BNPrintf(x);
        printf("\n");
	fprintf(stdout, "y = ");
	BNPrintf(y);
        printf("\n");
        printf("\n\n\n");

	EC_GROUP_get_order(group, order, ctx);
	if (!BN_nnmod(rp, x, order, ctx))
	{
		fprintf(stdout, " failed\n");
		goto builtin_err;
	}
	if (!BN_copy(kinv, z))
	{
		fprintf(stdout, " failed\n");
		goto builtin_err;
	}


//////////////////////////////////////////////////////
        printf("================================================\n");
        printf("Testing sign:\n");
        printf("digest=\n");
 	for(i=0;i<32;i++) {
 	    printf("%02X",digest[i]);
        }
 	printf("\n");

	fprintf(stdout, "kinv = ");
	BNPrintf(kinv);
        printf("\n");
	fprintf(stdout, "rp = ");
	BNPrintf(rp);
        printf("\n");
	fprintf(stdout, "order = ");
	BNPrintf(order);
        printf("\n");

	if (!SM2_sign_ex(1, digest, 32, signature, &sig_len, kinv, rp, eckey))
	{
		fprintf(stdout, " failed\n");
		goto builtin_err;
	}
        printf("sig_len=%d\n", sig_len);
        printf("signature=\n");
        for (i=0; i<sig_len; i++) {
            printf("%2.2x", signature[i]);
        }
        printf("\n");
	fprintf(stdout, "ECSign OK\n");
        printf("\n\n\n");

	/* verify signature */
	if (SM2_verify(1, digest, 32, signature, sig_len, eckey) != 1)
	{
		fprintf(stdout, " failed\n");
		goto builtin_err;
	}
#if 1
        signature_tmp = signature;
	d2i_ECDSA_SIG(&ecsig, &signature_tmp, sig_len);
#else
	d2i_ECDSA_SIG(&ecsig, &signature, sig_len);
#endif
        printf("ECVerify OK\n");
	fprintf(stdout, "r = ");
	BNPrintf(ecsig->r);
        printf("\n");
	fprintf(stdout, "s = ");
	BNPrintf(ecsig->s);
        printf("\n");
        printf("\n\n\n");

//////////////////////////////////////////////////////

#if 0
	//testing SM2DH vector
	/* create key */
	if (!BN_hex2bn(&z, "6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE")) ABORT;
	if (!EC_POINT_mul(group,P, z, NULL, NULL, ctx)) ABORT;
	if (!EC_POINT_get_affine_coordinates_GFp(group,P, x, y, ctx)) ABORT;
	fprintf(stdout, "\nTesting A Key Point\n     x = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n     y = 0x");
	BNPrintf( y);
	fprintf(stdout, "\n");
	EC_KEY_set_private_key(eckey,z);
	EC_KEY_set_public_key(eckey, P);

	if (!BN_hex2bn(&z, "5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53")) ABORT;
	if (!EC_POINT_mul(group,Q, z, NULL, NULL, ctx)) ABORT;
	if (!EC_POINT_get_affine_coordinates_GFp(group,Q, x, y, ctx)) ABORT;
	fprintf(stdout, "\nTesting B Key Point\n     x = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n     y = 0x");
	BNPrintf( y);
	fprintf(stdout, "\n");
	//EC_KEY_set_private_key(eckey,z);
	//EC_KEY_set_public_key(eckey, P);

	if (!BN_hex2bn(&z, "33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80")) ABORT;
	if (!EC_POINT_mul(group,P, z, NULL, NULL, ctx)) ABORT;
	if (!EC_POINT_get_affine_coordinates_GFp(group,P, x, y, ctx)) ABORT;
	fprintf(stdout, "\nTesting Rb Key Point\n     x = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n     y = 0x");
	BNPrintf( y);
	fprintf(stdout, "\n");

	if (!BN_hex2bn(&z, "83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563")) ABORT;
	if (!EC_POINT_mul(group,R, z, NULL, NULL, ctx)) ABORT;
	if (!EC_POINT_get_affine_coordinates_GFp(group,R, x, y, ctx)) ABORT;
	fprintf(stdout, "\nTesting Ra Key Point\n     x = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n     y = 0x");
	BNPrintf( y);
	fprintf(stdout, "\n");
    
	SM2_DH_key(group, P, Q, z,eckey,outkey,keylen);

	fprintf(stdout,"\nExchange key --KDF(Xv||Yv)--  :");
#if 1
	for(i=0; i<outlen; i++) {
            printf("%02X",outkey[i]);
        }
	printf("\n");
#endif
#endif

builtin_err:	
	OPENSSL_free(signature);
	signature = NULL;
	EC_POINT_free(P);
	EC_POINT_free(Q);
	EC_POINT_free(R);
	EC_POINT_free(DHPoint);
	EC_KEY_free(eckey);
	eckey = NULL;
	EC_GROUP_free(group);
	BN_CTX_free(ctx);

	return 0;

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
    EC_POINT    *P, *Q, *R;
    BIGNUM      *x, *y, *n;
    BIGNUM      *priv, *pubx, *puby;
    EC_KEY	*eckey = NULL;

    unsigned char	*signature, *signature_tmp;

    int	sig_len;
    int i;

    unsigned char	digest[32] = {
        0x54, 0x90, 0xfc, 0x4d,
        0xf4, 0x6a, 0xa3, 0x3f,
        0xc0, 0x8b, 0x40, 0x31,
        0x6d, 0x2d, 0x5d, 0x1f,
        0x42, 0x66, 0xfb, 0xf5,
        0x62, 0xb8, 0x08, 0xca,
        0x68, 0x51, 0xf6, 0xb0,
        0x21, 0x78, 0x50, 0x75};

    BIGNUM *kinv, *rp,*order; 

    ECDSA_SIG *ecsig = NULL;

    ecsig = ECDSA_SIG_new();
    if (!ecsig) ABORT;

    ctx = BN_CTX_new();
    if (!ctx) ABORT;

    p = BN_new();
    a = BN_new();
    b = BN_new();
    if (!p || !a || !b) ABORT;

    group = EC_GROUP_new(EC_GFp_mont_method());
    /* applications should use EC_GROUP_new_curve_GFp
    * so that the library gets to choose the EC_METHOD */
    if (!group) ABORT;

    printf("================================================\n");
    printf("set curve GFp\n");
    if (!BN_hex2bn(&p, SM2_P)) ABORT;
    if (1 != BN_is_prime_ex(p, BN_prime_checks, ctx, NULL)) ABORT;
    if (!BN_hex2bn(&a, SM2_A)) ABORT;
    if (!BN_hex2bn(&b, SM2_B)) ABORT;
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
    printf("Chinese sm2 algorithm test -- Generator:\n");
    P = EC_POINT_new(group);
    if (!P) ABORT;

    x = BN_new();
    y = BN_new();
    n = BN_new();
    if (!x || !y || !n) ABORT;

    if (!BN_hex2bn(&x, SM2_GX)) ABORT;
    if (!EC_POINT_set_compressed_coordinates_GFp(group, P, x, 0, ctx)) ABORT;
    if (!EC_POINT_is_on_curve(group, P, ctx)) ABORT;
    if (!BN_hex2bn(&n, SM2_N)) ABORT;
    if (!EC_GROUP_set_generator(group, P, n, BN_value_one())) ABORT;
    if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)) ABORT;
    fprintf(stdout, "n = ");
    BNPrintf(n);
    printf("\n");
    fprintf(stdout, "x = ");
    BNPrintf(x);
    printf("\n");
    fprintf(stdout, "y = ");
    BNPrintf(y);
    printf("\n");
    printf("\n\n\n");

    printf("================================================\n");
    printf("Create key:\n");
    if ((eckey = EC_KEY_new()) == NULL)
        goto builtin_err;
    if (EC_KEY_set_group(eckey, group) == 0)
    {
        fprintf(stdout," failed\n");
        goto builtin_err;
    }

    priv = BN_new();
    pubx = BN_new();
    puby = BN_new();
    if (!priv || !pubx || !puby) ABORT;

    if (!BN_hex2bn(&priv, SM2_PRIV)) ABORT;
    if (!EC_POINT_mul(group, P, priv, NULL, NULL, ctx)) ABORT;
    if (!EC_POINT_get_affine_coordinates_GFp(group, P, pubx, puby, ctx)) ABORT;
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

    EC_KEY_set_private_key(eckey, priv);
    EC_KEY_set_public_key(eckey, P);

    /* check key */
    if (!EC_KEY_check_key(eckey))
    {
        fprintf(stdout," failed\n");
        goto builtin_err;
    }

    /* create signature */
    sig_len = ECDSA_size(eckey);
    //fprintf(stdout,"Siglength is: %d \n",sig_len);
    if ((signature = OPENSSL_malloc(sig_len)) == NULL)
        goto builtin_err;

#if 0
    rp    = BN_new();
    kinv  = BN_new();
    order = BN_new();

    EC_GROUP_get_order(group, order, ctx);
    if (!BN_nnmod(rp, pubx, order, ctx))
    {
        fprintf(stdout, " failed\n");
        goto builtin_err;
    }
    if (!BN_copy(kinv, priv))
    {
        fprintf(stdout, " failed\n");
        goto builtin_err;
    }

    fprintf(stdout, "kinv = ");
    BNPrintf(kinv);
    printf("\n");
    fprintf(stdout, "rp = ");
    BNPrintf(rp);
    printf("\n");
    fprintf(stdout, "order = ");
    BNPrintf(order);
    printf("\n");
#endif

    printf("================================================\n");
    printf("Testing sign:\n");
    printf("digest=\n");
    for(i=0; i<32; i++) {
        printf("%02X", digest[i]);
    }
    printf("\n");

#if 1
    ecsig = sm2_do_sign(digest, 32, priv, pubx, eckey);
#else
    if (!SM2_sign_ex(1, digest, 32, signature, &sig_len, priv, pubx, eckey))
    {
        fprintf(stdout, " failed\n");
        goto builtin_err;
    }

    printf("sig_len=%d\n", sig_len);
    printf("signature=\n");
    for (i=0; i<sig_len; i++) {
        printf("%2.2x", signature[i]);
    }
    printf("\n");

    if (SM2_verify(1, digest, 32, signature, sig_len, eckey) != 1)
    {
        fprintf(stdout, " failed\n");
        goto builtin_err;
    }

    signature_tmp = signature;
    d2i_ECDSA_SIG(&ecsig, &signature_tmp, sig_len);
#endif
    fprintf(stdout, "r = ");
    BNPrintf(ecsig->r);
    printf("\n");
    fprintf(stdout, "s = ");
    BNPrintf(ecsig->s);
    printf("\n");
    printf("\n\n\n");

builtin_err:	
    OPENSSL_free(signature);
    signature = NULL;
    EC_POINT_free(P);
    //EC_POINT_free(Q);
    //EC_POINT_free(R);
    EC_KEY_free(eckey);
    eckey = NULL;
    EC_GROUP_free(group);
    BN_CTX_free(ctx);

    return 0;
}

int main()
{
	CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	ERR_load_crypto_strings();
	RAND_seed(rnd_seed, sizeof rnd_seed); 
	
	SM2_Test_Vecotor2();
	SM2_Test_Vecotor3();
	
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	ERR_remove_state(0);
	CRYPTO_mem_leaks_fp(stderr);
	
	return 0;

}

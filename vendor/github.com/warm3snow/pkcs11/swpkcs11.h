/* swpkcs11.h include file for PKCS #11. */
/* $Revision: 1.0 $ */

/* This header file contains pretty much everything about all the */
/* Cryptoki function prototypes.  Because this information is */
/* used for more than just declaring function prototypes, the */
/* order of the functions appearing herein is important, and */
/* should not be altered. */

#ifndef _SWPKCS11_H_
#define _SWPKCS11_H_ 1


#define CKM_VENDOR_DEFINED             0x80000000


#ifdef DEPT3_EXTENSION
#define CKK_SSF33                     (CKK_VENDOR_DEFINED + 3)
#define CKK_SM1                       (CKK_VENDOR_DEFINED + 2)
#else
#define CKK_SSF33                     (CKK_VENDOR_DEFINED + 2)
#define CKK_SM1                       (CKK_VENDOR_DEFINED + 3)
#endif

#define CKK_SM2                       (CKK_VENDOR_DEFINED + 4)
#define CKK_SM3                       (CKK_VENDOR_DEFINED + 5)
//add for SM4, zhaoxueqiang
#ifdef ITRUS_EXTENSION
#define CKK_SM4                       (CKK_VENDOR_DEFINED + 6)
#else
#define CKK_SM4                       (CKK_VENDOR_DEFINED + 0x00000106)
#endif


//add by zhaoxueqiang for itrus defines
#ifdef ITRUS_EXTENSION
#define CKM_SSF33								(CKM_VENDOR_DEFINED + 0x6000)
#define CKM_SSF33_KEY_GEN				(CKM_SSF33 + 0x0001)
#define CKM_SSF33_ECB						(CKM_SSF33 + 0x0100)
#define CKM_SSF33_ECB_PAD				(CKM_SSF33 + 0x0101) 
#define CKM_SSF33_CBC						(CKM_SSF33 + 0x0200)
#define CKM_SSF33_CBC_PAD				(CKM_SSF33 + 0x0201)
#define CKM_SM1								(CKM_VENDOR_DEFINED + 0x7000)
#define CKM_SM1_KEY_GEN				(CKM_SM1 + 0x0001)
#define CKM_SM1_ECB						(CKM_SM1 + 0x0100)
#define CKM_SM1_ECB_PAD				(CKM_SM1 + 0x0101)
#define CKM_SM1_CBC						(CKM_SM1 + 0x0200)
#define CKM_SM1_CBC_PAD				(CKM_SM1 + 0x0201)
#define CKM_SCB2_MAC						(CKM_VENDOR_DEFINED + 18)
#define CKM_SCB2_MAC_GENERAL		(CKM_VENDOR_DEFINED + 19)
#define CKM_RSA_RAW						(CKM_VENDOR_DEFINED + 0x2000) 
#define CKM_JNMASTER_KEY_ENC		(CKM_VENDOR_DEFINED + 0x1061)
#define CKM_SM4								(CKM_VENDOR_DEFINED + 0xA000)
#define CKM_SM4_KEY_GEN				(CKM_SM4 + 0x0001)
#define CKM_SM4_ECB						(CKM_SM4 + 0x0100)
#define CKM_SM4_ECB_PAD				(CKM_SM4 + 0x0101)
#define CKM_SM4_CBC						(CKM_SM4 + 0x0200)
#define CKM_SM4_CBC_PAD				(CKM_SM4 + 0x0201)
#elif defined DEPT3_EXTENSION
#define CKM_SSF33_KEY_GEN             (CKM_VENDOR_DEFINED + 0x4113)
#define CKM_SSF33_ECB                 (CKM_VENDOR_DEFINED + 0x1061)
#define CKM_SSF33_CBC                 (CKM_VENDOR_DEFINED + 3)
#define CKM_SSF33_CBC_PAD             (CKM_VENDOR_DEFINED + 4)
#define CKM_SSF33_ECB_PAD             (CKM_VENDOR_DEFINED + 5) 
#define CKM_SM1_KEY_GEN               (CKM_VENDOR_DEFINED + 6)
#define CKM_SM1_ECB                   (CKM_VENDOR_DEFINED + 7) 
#define CKM_SM1_CBC                   (CKM_VENDOR_DEFINED + 8) 
#define CKM_SM1_ECB_PAD               (CKM_VENDOR_DEFINED + 9) 
#define CKM_SM1_CBC_PAD               (CKM_VENDOR_DEFINED + 10) 
#define CKM_RSA_RAW                   (CKM_VENDOR_DEFINED + 0x100001) 
#define CKM_JNMASTER_KEY_ENC          (CKM_VENDOR_DEFINED + 0x1323442)
#elif defined UPKCS11_STD
#define CKM_SSF33_KEY_GEN             (CKM_VENDOR_DEFINED + 1)
#define CKM_SSF33_ECB                 (CKM_VENDOR_DEFINED + 2)
#define CKM_SSF33_CBC                 (CKM_VENDOR_DEFINED + 3)
#define CKM_SSF33_CBC_PAD             (CKM_VENDOR_DEFINED + 4)
#define CKM_SSF33_ECB_PAD             (CKM_VENDOR_DEFINED + 5) 
#define CKM_SM1_KEY_GEN               (CKM_VENDOR_DEFINED + 6)
#define CKM_SM1_ECB                   (CKM_VENDOR_DEFINED + 7) 
#define CKM_SM1_CBC                   (CKM_VENDOR_DEFINED + 8) 
#define CKM_SM1_ECB_PAD               (CKM_VENDOR_DEFINED + 9) 
#define CKM_SM1_CBC_PAD               (CKM_VENDOR_DEFINED + 10) 
#define CKM_RSA_RAW                   (CKM_VENDOR_DEFINED + 11) 
#define CKM_JNMASTER_KEY_ENC          (CKM_VENDOR_DEFINED + 0x1323442)
#else
#define CKM_SSF33_KEY_GEN             (CKM_VENDOR_DEFINED + 9)
#define CKM_SSF33_ECB                 (CKM_VENDOR_DEFINED + 10)
#define CKM_SSF33_CBC                 (CKM_VENDOR_DEFINED + 11)
#define CKM_SSF33_CBC_PAD             (CKM_VENDOR_DEFINED + 12)
#define CKM_SSF33_ECB_PAD             (CKM_VENDOR_DEFINED + 13) 
//#define CKM_SSF33_CBC                 (CKM_VENDOR_DEFINED + 0x1001)
//#define CKM_SSF33_CBC_PAD             (CKM_VENDOR_DEFINED + 0x1002)
//#define CKM_SSF33_ECB_PAD             (CKM_VENDOR_DEFINED + 0x1003) 
#define CKM_SM1_KEY_GEN               (CKM_VENDOR_DEFINED + 15)
#define CKM_SM1_ECB                   (CKM_VENDOR_DEFINED + 16)
#define CKM_SM1_CBC                   (CKM_VENDOR_DEFINED + 17)
#define CKM_SCB2_MAC                  (CKM_VENDOR_DEFINED + 18)
#define CKM_SCB2_MAC_GENERAL          (CKM_VENDOR_DEFINED + 19)
#define CKM_SM1_ECB_PAD               (CKM_VENDOR_DEFINED + 0x1004) 
#define CKM_SM1_CBC_PAD               (CKM_VENDOR_DEFINED + 22)
#define CKM_RSA_RAW                   (CKM_VENDOR_DEFINED + 0x2000) 
#define CKM_JNMASTER_KEY_ENC          (CKM_VENDOR_DEFINED + 0x1061)
//add for SM4, zhaoxueqiang
#define CKM_SM4_KEY_GEN                   (CKM_VENDOR_DEFINED + 0x00000107)
#define CKM_SM4_ECB                       (CKM_VENDOR_DEFINED + 0x00000108)
#define CKM_SM4_CBC                       (CKM_VENDOR_DEFINED + 0x00000109)
#define CKM_SM4								(CKM_VENDOR_DEFINED + 0xA000)
#define CKM_SM4_ECB_PAD				(CKM_SM4 + 0x0101)
#define CKM_SM4_CBC_PAD				(CKM_SM4 + 0x0201)
#endif


// /* the following mechanism types are defined for SM2: */
// SM2 Base define
#define CKM_SM2										(CKM_VENDOR_DEFINED + 0x8000)
// SM2 Generate Key paire
#define CKM_SM2_KEY_PAIR_GEN			(CKM_SM2 + 0x00000001)
/* SM2 Signature */
// SM2 Signature with SM3 Digest
#define CKM_SM3_SM2								(CKM_SM2 + 0x00000100)
// DerCoding SM2 Signature with SM3 Digest
#define CKM_SM3_SM2_DER					(CKM_SM2 + 0x00000101)
// SM2 Signature with SM3 Digest & Application ID "1234567812345678"
#define CKM_SM3_SM2_APPID1				(CKM_SM2 + 0x00000102)
// DerCoding SM2 Signature with SM3 Digest & Application ID "1234567812345678"
#define CKM_SM3_SM2_APPID1_DER		(CKM_SM2 + 0x00000103)
#define CKM_SM3_SM2_Z							CKM_SM3_SM2_APPID1
#define CKM_SM3_SM2_Z_DER				CKM_SM3_SM2_APPID1_DER
//SM2 Signature without SM3 Digest
#define CKM_SM2_SIGN							(CKM_SM2 + 0x00000104)
#define CKM_SM2_SIGN_NO_DER			(CKM_SM2 + 0x00000105)

// SM2 Crypto
// SM2 Crypto 32 bytes data pad 0x00
#define CKM_SM2_RAW                 (CKM_SM2 + 0x00000200)
// SM2 Crypto 32 bytes data pad 0x00
#define CKM_SM2_CIPHER_DER          (CKM_SM2 + 0x00000201)
#define CKM_SM2_RAW_DER				CKM_SM2_CIPHER_DER
// SM2 Signature
// SM2 Signature with SHA-160/SHA-1 Digest
#define CKM_SHA_160_SM2             (CKM_SM2 + 0x00000300)
// Compatible with older version
#define CKM_SM2_SHA_160             CKM_SHA_160_SM2
// DerCoding SM2 Signature with SHA-160/SHA-1 Digest
#define CKM_SHA_160_SM2_DER         (CKM_SM2 + 0x00000301)
#define CKM_SM2_SHA1					CKM_SHA_160_SM2
#define CKM_SM2_SHA1_DER			CKM_SHA_160_SM2_DER
// SM2 Signature with SHA-256 Digest
#define CKM_SHA_256_SM2             (CKM_SM2 + 0x00000400)
// Compatible with older version
#define CKM_SM2_SHA_256             CKM_SHA_256_SM2
// DerCoding SM2 Signature with SHA-160/SHA-1 Digest
#define CKM_SHA_256_SM2_DER         (CKM_SM2 + 0x00000401)


#define CKM_SM3                        (CKM_VENDOR_DEFINED + 0x9000)
#define CKM_SM3_HASH                    (CKM_SM3 + 0x00000001)
#define CKM_SM3_HASH_JIT                (CKK_VENDOR_DEFINED + 5)


//for IBM
#define CKK_IBM_SM4											0x80050001
#define CKK_IBM_SM2											0x80050002
#define CKM_IBM_SM2_KEY_PAIR_GEN					0x8005000A
#define CKM_IBM_SM2											0x8005000B
#define CKM_IBM_SM2_SM3								0x8005000C
#define CKM_IBM_SM2_ENCRYPT							0x8005000D
#define CKM_IBM_SM3											0x8005000E
#define CKM_IBM_SM4_KEY_GEN							0x80050001
#define CKM_IBM_SM4_ECB									0x80050004
#define CKM_IBM_SM4_CBC									0x80050002
#define CKM_IBM_SM4_MAC_GENERAL				0x80050007
#define CKM_IBM_SM4_MAC								0x80058007
#define CKM_IBM_ISO2_SM4_MAC_GENERAL		0x80050008
#define CKM_IBM_ISO2_SM4_MAC						0x80058008
#define CKM_IBM_SM4_ECB_ENCRYPT_DATA		0x80050009
#define CKM_IBM_TRANSPORTKEY						0x80020005
//#define CKM_XOR_BASE_AND_DATA						0x00000364



#endif	//#ifndef _SWPKCS11_H_


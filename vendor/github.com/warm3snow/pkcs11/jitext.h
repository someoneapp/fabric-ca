/*
* This file is part of PKCS11. 
* (c) 2008,2009 Beijing Sansec Technology Development Co.,Ltd.
*/
/*
* NAME:         jitext.h
* DESCRIPTION:  -
* AUTHOR:       Sansec
* BUGS: *       -
* HISTORY:
* HISTORY:      Revision 1.0  2009/07/22 Sansec
* HISTORY:      Initial revision
* HISTORY:
*/

CK_PKCS11_FUNCTION_INFO(C_SignXX)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,        /* 输入：会话句柄 */
  CK_OBJECT_HANDLE	hKey,
  CK_BYTE_PTR       pData,           /* 输入：数据源 */
  CK_ULONG          ulDataLen,       /* 输入：数据源长度 */
  CK_BYTE_PTR       pSignature,      /* 输出：签名 */
  CK_ULONG_PTR      pulSignatureLen  /* 输入输出：签名长度 */
 );
#endif

/* 单包签名验证. */
CK_PKCS11_FUNCTION_INFO(C_VerifyXX)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE 		hSession,       /* 输入：会话句柄 */
  CK_OBJECT_HANDLE			hKey,
  CK_BYTE_PTR       		pSignature,     /* 输入：签名 */
  CK_ULONG          		ulSignatureLen,
  CK_BYTE_PTR       		pData,
  CK_ULONG_PTR      		ulDataLen
 );
#endif

CK_PKCS11_FUNCTION_INFO(C_SignEx)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE				hSession,
  CK_MECHANISM_PTR     		pMechanism,//xmy add
  CK_OBJECT_HANDLE				hKey,
  CK_ATTRIBUTE_PTR				pTemplate,
  CK_ULONG								ulCount,
  CK_BYTE_PTR							pData,
  CK_ULONG						 		ulDataLen,
  CK_BYTE_PTR							pSignature,
  CK_ULONG_PTR						pulSignatureLen
 );
#endif

CK_PKCS11_FUNCTION_INFO(C_VerifyEx)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE			hSession,
  CK_MECHANISM_PTR     	pMechanism,
  CK_OBJECT_HANDLE			hKey,
  CK_ATTRIBUTE_PTR			pTemplate,
  CK_ULONG							ulCount,
  CK_BYTE_PTR						pSignature,
  CK_ULONG						 	ulSignatureLen,
  CK_BYTE_PTR						pData,
  CK_ULONG_PTR					pulDataLen
 );
#endif

/* 单包对称加密 */
CK_PKCS11_FUNCTION_INFO(C_EncryptEx)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE				hSession,
  CK_MECHANISM_PTR				pMechanism,
  CK_OBJECT_HANDLE				hKey,
  CK_ATTRIBUTE_PTR				pTemplate,
  CK_ULONG								ulCount,
  CK_BYTE_PTR							pData,
  CK_ULONG						 		ulDataLen,
  CK_BYTE_PTR							pEncryptedData,
  CK_ULONG_PTR						pulEncryptedDataLen,
  CK_ULONG_PTR						pulKeyLen
 );
#endif

/* 单包对称解密 */
CK_PKCS11_FUNCTION_INFO(C_DecryptEx)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE				hSession,
  CK_MECHANISM_PTR				pMechanism,
  CK_OBJECT_HANDLE				hKey,
  CK_ATTRIBUTE_PTR				pTemplate,
  CK_ULONG								ulCount,
  CK_BYTE_PTR							pEncryptedData,
  CK_ULONG						 		ulEncryptedDataLen,
  CK_BYTE_PTR							pData,
  CK_ULONG_PTR						pulDataLen,
  CK_ULONG_PTR						pulKeyLen
 );
#endif


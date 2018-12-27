/* conf.h.  */

/* define if the code is compiled on a UNIX machine */
#ifndef WIN32
#define CK_GENERIC 1
#endif

/* define if the code is compiled on a Win32 machine */
//delete by zhaoxueqiang for linux, win32 define in project property
#ifdef WIN32
#define CK_Win32 1
#endif

/* Define if you have the <pthread.h> header file.  */
#define HAVE_PTHREAD_H 1

/* Define if you have the <unistd.h> header file.  */
#ifndef WIN32
#define HAVE_UNISTD_H 1
#endif

/*  the maximum number of signals  */
#define MAX_SIG_NUM _NSIG 

/* Version number of package */
#define VERSION "0.7.2"

/* major version number of cryptoki that this implements */
/*#define CRYPTOKI_VERSION_MAJOR 2*/

/* minor version number of cryptoki that this implements */
/*#define CRYPTOKI_VERSION_MINOR 01*/

/* major version number of gpkcs11 */
#define LIBRARY_VERSION_MAJOR 2

/* minor version number of gpkcs11 */
#define LIBRARY_VERSION_MINOR 18





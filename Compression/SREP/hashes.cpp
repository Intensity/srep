// Copyright (C) 2009-2014 Bulat Ziganshin. All rights reserved.
// Mail Bulat.Ziganshin@gmail.com if you have any questions or want to buy a commercial license for the source code.

// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// LibTomCrypt: SHA-1, MD5 & Fortuna CPRNG  *********************************************************************************************************
// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define MD5_SIZE    16
#define SHA1_SIZE   20
#define SHA512_SIZE 64
typedef unsigned char Digest[SHA1_SIZE];

#define LTC_NO_HASHES
#define   LTC_MD5
#define   LTC_SHA1
#define   LTC_SHA512
#define LTC_NO_CIPHERS
#define   LTC_RIJNDAEL
#define     ENCRYPT_ONLY

// crypt_argchk.c and aes.c are included via vmac.h below
//#include "crypt/crypt_argchk.c"
//#include "ciphers/aes/aes.c"
#include "hashes/md5.c"
#include "hashes/sha1.c"
#include "hashes/sha2/sha512.c"
#include "prngs/fortuna.c"
#include "misc/zeromem.c"

void compute_sha1 (void*, void *buf, int size, void *result)
{
  hash_state state;
  sha1_init    (&state);
  sha1_process (&state, (unsigned char*)buf, (unsigned long)size);
  sha1_done    (&state, (unsigned char*)result);
}

void compute_md5 (void*, void *buf, int size, void *result)
{
  hash_state state;
  md5_init    (&state);
  md5_process (&state, (unsigned char*)buf, (unsigned long)size);
  md5_done    (&state, (unsigned char*)result);
}

void compute_sha512 (void*, void *buf, int size, void *result)
{
  hash_state state;
  sha512_init    (&state);
  sha512_process (&state, (unsigned char*)buf, (unsigned long)size);
  sha512_done    (&state, (unsigned char*)result);
}

void cryptographic_prng (void *result, size_t size)
{
  static prng_state prng[1];
  static bool initialized = false;

  if (!initialized)
  {
    fortuna_start(prng);
    const int size=4096;
    unsigned char buf[size];
    int bytes = systemRandomData (buf,size);
    fortuna_add_entropy (buf, bytes, prng);
    time((time_t*)buf);
    fortuna_add_entropy (buf, sizeof(time_t), prng);
    fortuna_ready (prng);
    initialized = true;
  }

  fortuna_read ((unsigned char *)result, size, prng);
}


// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Hash functions ***********************************************************************************************************************************
// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// hash содержит значение хеш-функции от последних L обработанных байт, для удобства обновления используется скользящая хеш-функция.
// constructor(buf,L,seed) создаёт хеш, параметризованный seed, и инициализирует его первыми L байтами буфера
// update(sub,add) выносит из хеша байт sub и добавляет байт add.

template <class ValueT>
struct FakeRollingHash
{
  operator ValueT ()                               {return 0;}
  FakeRollingHash (void *buf, int L, ValueT seed)  {}
  void update     (BYTE sub, BYTE add)             {}
};


// Возведение в степень
template <class T>
T power (T base, unsigned n)
{
  T result = 1;
  while (n) {
    if (n % 2)  result*=base, n--;
    n /= 2;  base*=base;
  }
  return result;
}

template <class ValueT>
struct PolynomialHash
{
  operator ValueT()  {return value;}
  ValueT value, PRIME;

  PolynomialHash (ValueT seed) : value(0), PRIME(seed) {}

  PolynomialHash (void *buf, int L, ValueT seed) : value(0), PRIME(seed)
  {
    update (buf, L);
  }

  void update (BYTE b)
  {
    value = value*PRIME + b;
  }

  void update (void *buf, int L)
  {
    for (NUMBER i=0; i<L; i++)  update (((BYTE*)buf)[i]);
  }
};

template <class ValueT>
struct PolynomialRollingHash
{
  operator ValueT()  {return value;}
  ValueT value, PRIME, PRIME2, PRIME3, PRIME4, PRIME5, PRIME6, PRIME7, PRIME8, PRIME_L, PRIME_L1, PRIME_L2, PRIME_L3;
  int L;

  PolynomialRollingHash (int _L, ValueT seed)
  {
    L = _L;
    PRIME8 = seed * (PRIME7 = seed * (PRIME6 = seed * (PRIME5 = seed * (PRIME4 = seed * (PRIME3 = seed * (PRIME2 = seed * (PRIME = seed)))))));
    PRIME_L3 = seed * (PRIME_L2 = seed * (PRIME_L1 = seed * (PRIME_L = power(PRIME,L))));
  }

  PolynomialRollingHash (void *buf, int _L, ValueT seed)
  {
    L = _L;
    PRIME8 = seed * (PRIME7 = seed * (PRIME6 = seed * (PRIME5 = seed * (PRIME4 = seed * (PRIME3 = seed * (PRIME2 = seed * (PRIME = seed)))))));
    PRIME_L3 = seed * (PRIME_L2 = seed * (PRIME_L1 = seed * (PRIME_L = power(PRIME,L))));
    moveto (buf);
  }

  void update (BYTE sub, BYTE add)
  {
    value = value*PRIME + add - PRIME_L*sub;
  }

  // Roll hash by N==power(2,x) bytes
  template <int N>
  void update (void *_ptr)
  {
    BYTE *ptr = (BYTE*) _ptr;
    switch(N%4)
    {
    case 0:   break;

    case 1:   value = value*PRIME + ptr[L] - PRIME_L*ptr[0]; break;

    case 2:   value = value*PRIME2 + PRIME*ptr[L] + ptr[L+1]
                                   - PRIME_L1*ptr[0] - PRIME_L*ptr[1]; break;

    case 3:   value = value*PRIME3 + PRIME2*ptr[L] + PRIME*ptr[L+1] + ptr[L+2]
                                   - PRIME_L2*ptr[0] - PRIME_L1*ptr[1] - PRIME_L*ptr[2]; break;
    }

    for (int i=0; i<N/4; i++, ptr+=4)
      value = value*PRIME4 + PRIME3*ptr[N%4+L] + PRIME2*ptr[N%4+L+1] + PRIME*ptr[N%4+L+2] + ptr[N%4+L+3]
                           - PRIME_L3*ptr[N%4+0] - PRIME_L2*ptr[N%4+1] - PRIME_L1*ptr[N%4+2] - PRIME_L*ptr[N%4+3];
  }

  void moveto (void *_buf);
};

template <class ValueT>
void PolynomialRollingHash<ValueT>::moveto (void *_buf)
{
  value = 0;  BYTE *buf = (BYTE*) _buf;
  const int N=16, S=4;
  for (int i=0; i < (L&~(N-1)); i+=N)
  {
#   define STEP(n)   (value = value*PRIME4 + PRIME3*buf[i+(n)*S] + PRIME2*buf[i+1+(n)*S] + PRIME*buf[i+2+(n)*S] + buf[i+3+(n)*S])
    STEP(0); if (N>S) STEP(1); if (N>2*S) {STEP(2); STEP(3);} if (N>4*S) {STEP(4); STEP(5); STEP(6); STEP(7);}
  }
  for (int i = L&~(N-1); i<L; i++)
    value = value*PRIME + buf[i];
}

// Large 32-bit primes suitable for seeding the polynomial hash
const uint32  PRIME1 = 153191,  PRIME2 = 3141601;


// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CRC hashing **************************************************************************************************************************************
// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if GCC_VERSION >= 403

// Requires GCC4.3 and SSE4.2-enabled CPU; and of course compatible only with Crc32CastagnoliPolynom
#include <x86intrin.h>
#include <cpuid.h>
uint32 a_mm_crc32_u8(uint32 crc, uint8 value) {
  asm("crc32b %[value], %[crc]\n" : [crc] "+r" (crc) : [value] "rm" (value));
  return crc;
}
#define update_CRC(crc,CRCTable,c)  (a_mm_crc32_u8((crc),(c)))

bool crc32c()  /* Check CPU for CRC32c asm instruction support (part of SSE4.2) */
{
  uint32 eax, ebx, ecx, edx;
  __get_cpuid(1, &eax, &ebx, &ecx, &edx);
  return (ecx & bit_SSE4_2) != 0;
}

#else

#define update_CRC(crc,CRCTable,c)  (CRCTable[((crc)^(c)) & 0xFF] ^ ((crc)>>8))
#define crc32c()                    false    /* CRC32c asm instruction isn't supported */

#endif

template <class ValueT>
struct CrcRollingHash
{
  operator ValueT()  {return value;}
  ValueT value, CRCTab[256], RollingCRCTab[256];
  NUMBER L;

  CrcRollingHash (           int _L, ValueT seed)   {init (_L, seed);}
  CrcRollingHash (void *buf, int _L, ValueT seed)   {init (_L, seed);  moveto (buf);}

  void init (int L, ValueT seed);

  // Calculate initial hash value
  void moveto (void *buf)
  {
    value = 0;
    for (NUMBER i=0; i<L; i++)  update (0, ((BYTE*)buf)[i]);
  }

  void update (BYTE sub, BYTE add)
  {
    value = update_CRC(value,CRCTab,add) ^ RollingCRCTab[sub];
  }
};

// Fast CRC table construction algorithm
template <class ValueT>
void FastTableBuild (ValueT CRCTable[256], ValueT seed, ValueT CrcPolynom)
{
  ValueT crc    = seed;
  CRCTable[0]   = 0;
  CRCTable[128] = crc;
  for (NUMBER i=64; i; i/=2)
    CRCTable[i] = crc = (crc >> 1) ^ (CrcPolynom & ~((crc & 1) - 1));

  for (NUMBER i=2; i<256; i*=2)
    for (NUMBER j=1; j<i; j++)
      CRCTable[i+j] = CRCTable[i] ^ CRCTable[j];
}

// Calculate CRC of buffer
template <class ValueT>
ValueT calcCRC (BYTE *buffer, int len, ValueT CRCTable[256])
{
  ValueT crc = 0;
  for (NUMBER i=0; i<len; i++)
    crc = update_CRC (crc, CRCTable, buffer[i]);
  return crc;
}

template <class ValueT>
void CrcRollingHash<ValueT>::init (int _L, ValueT CrcPolynom)
{
  L = _L;

  // Fast CRC table construction
  FastTableBuild (CRCTab, CrcPolynom, CrcPolynom);

  // Fast table construction for rolling CRC
  ValueT crc = update_CRC(0,CRCTab,128);
  for (NUMBER i=0; i<L; i++)
    crc = update_CRC (crc, CRCTab, 0);
  FastTableBuild (RollingCRCTab, crc, CrcPolynom);
}

// Some popular CRC polynomes
const uint32 Crc32IeeePolynom = 0xEDB88320;
const uint32 Crc32CastagnoliPolynom = 0x82F63B78;
const uint64 Crc64EcmaPolynom = 0xC96C5795D7870F42ULL;


// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SIPHASH: keyed cryptographic hash ****************************************************************************************************************
// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "siphash/siphash.c"
#define SIPHASH_TAG_LEN_BYTES 8
#define SIPHASH_KEY_LEN_BYTES 16

void* new_siphash (void *seed, int size)
{
  if (size!=SIPHASH_KEY_LEN_BYTES)
    return NULL;
  void *key = malloc(SIPHASH_KEY_LEN_BYTES);
  memcpy (key, seed, SIPHASH_KEY_LEN_BYTES);
  return key;
}

void compute_siphash (void *key, void *buf, int size, void *result)
{
  *(uint64_t*)result = siphash ((unsigned char *)key, (const unsigned char *)buf, size);
}


// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// VHASH: keyed cryptographic hash ******************************************************************************************************************
// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define VMAC_TAG_LEN     128  /* Requesting VMAC-128 algorithm (instead of VMAC-64) */
#define VMAC_KEY_LEN     256  /* Must be 128, 192 or 256 (AES key size)        */
#define VMAC_NHBYTES     4096 /* Must 2^i for any 3 < i < 13. Standard = 128   */
#define VMAC_USE_LIB_TOM_CRYPT 1
#include "vmac/vmac.c"
#define VMAC_ALIGNMENT   16   /* SSE-compatible memory alignment */
#define VMAC_TAG_LEN_BYTES (VMAC_TAG_LEN/CHAR_BIT)
#define VMAC_KEY_LEN_BYTES (VMAC_KEY_LEN/CHAR_BIT)

struct VHash
{
  bool initialized;
  ALIGN(VMAC_ALIGNMENT) vmac_ctx_t ctx;

  VHash() : initialized(false) {}

  // Initialize ctx
  void init (void *seed = NULL)
  {
    if (!initialized || seed)
    {
      ALIGN(4) unsigned char key[VMAC_KEY_LEN_BYTES];
      if (seed)  memcpy (key, seed, VMAC_KEY_LEN_BYTES);
      else       cryptographic_prng (key, VMAC_KEY_LEN_BYTES);
      vmac_set_key(key, &ctx);
      initialized = true;
    }
  }

  // Return hash value for the buffer
  void compute (const void *ptr, size_t size, void *result)
  {
    uint64_t res, tagl;
    init();

    res = vhash((unsigned char*)ptr, size, &tagl, &ctx);

    ((uint64_t*)result)[0] = res;
    if (VMAC_TAG_LEN==128)
      ((uint64_t*)result)[1] = tagl;
  }
};

void* new_vhash (void *seed, int size)
{
  if (size!=VMAC_KEY_LEN_BYTES)
    return NULL;
  VHash *h = new VHash;
  h->init(seed);
  return h;
}

void compute_vhash (void *hash, void *buf, int size, void *result)
{
  ((VHash *)hash)->compute(buf, size, result);
}


// Using VHash instead of SHA-1 for digest
struct VDigest
{
  VHash vhash1, vhash2;
  void init()  {vhash1.init(); vhash2.init();}
  void compute (const void *ptr, size_t size, void *result)
  {
    vhash1.compute (ptr, size, result);
    vhash2.compute (ptr, size, (BYTE*)result + sizeof(Digest) - VMAC_TAG_LEN_BYTES);
  }
};



// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Hash descriptors *********************************************************************************************************************************
// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Function returning hash object initialized by the provided seed
typedef void* (*new_hash_t) (void *seed, int size);

// Hash function processing the (buf,size) and storing computed hash value to the result
typedef void (*hash_func_t) (void *hash, void *buf, int size, void *result);

// Description for various hash algorithms
struct hash_descriptor {
  char*        hash_name;           // name used in the -hash=... option
  unsigned     hash_num;            // numeric tag stored in the archive header
  unsigned     hash_seed_size;      // additional bytes stored in the archive header (seed value for randomized hashes)
  unsigned     hash_size;           // bytes stored in the each block (hash value)
  new_hash_t   new_hash;            // create hash object
  hash_func_t  hash_func;           // hash function
} hash_descriptors[] = {{"md5",     0,  0,                      MD5_SIZE,               0,            compute_md5},
                        {"",        1,  0,                      MD5_SIZE,               0,            0},
                        {"sha1",    2,  0,                      SHA1_SIZE,              0,            compute_sha1},
                        {"sha512",  3,  0,                      SHA512_SIZE,            0,            compute_sha512},
                        {"vmac",    4,  VMAC_KEY_LEN_BYTES,     VMAC_TAG_LEN_BYTES,     new_vhash,    compute_vhash},
                        {"siphash", 5,  SIPHASH_KEY_LEN_BYTES,  SIPHASH_TAG_LEN_BYTES,  new_siphash,  compute_siphash},
                       };

const char *DEFAULT_HASH = "vmac",  *HASH_LIST = "vmac(default)/siphash/md5/sha1/sha512";

// Find hash descriptor by the hash name
struct hash_descriptor *hash_by_name (const char *hash_name, int &errcode)
{
  if (errcode)  return NULL;
  for (int i=0; i<elements(hash_descriptors); i++)
    if (strcasecmp (hash_descriptors[i].hash_name, hash_name) == EQUAL)
      {errcode=0; return &hash_descriptors[i];}
  errcode=1; return NULL;
}

// Find hash descriptor by the hash tag
struct hash_descriptor *hash_by_num (int hash_num)
{
  for (int i=0; i<elements(hash_descriptors); i++)
    if (hash_descriptors[i].hash_num == hash_num)
      return &hash_descriptors[i];
  return NULL;
}

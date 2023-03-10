// Copyright (C) 2009-2014 Bulat Ziganshin. All rights reserved.
// Mail Bulat.Ziganshin@gmail.com if you have any questions or want to buy a commercial license for the source code.

// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Hash table ***************************************************************************************************************************************
// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef size_t HashValue;            // Hash of L-byte block, used as first step to find the match
typedef uint32 StoredHashValue;      // Hash value stored in hasharr[]
typedef uint64 BigHash;              // We need 64 bits for storing index+value in the chunkarr+hasharr
typedef uint32 Chunk;                // Uncompressed file are splitted into L-byte chunks, it's the number of chunk in the file
const Chunk  MAX_CHUNK = Chunk(-1),  NOT_FOUND = 0;
const int MAX_HASH_CHAIN = 12;

#define min_hash_size(n)   (((n)/4+1)*5)     /* Minimum size of hash for storing n elements */


// Improves EXHAUSTIVE_SEARCH by filtering out ~90% of false matches
struct SliceHash
{
  typedef uint32 entry;
  static const NUMBER BITS=4, ONES=(1<<BITS)-1;   // how much bits used from every calculated hash

  entry *h;  // Array holding all slice hashes, one `entry` per L bytes
  Offset memreq;
  int check_slices, errcode;
  NUMBER L, slices_in_block, slice_size;

  SliceHash (Offset filesize, unsigned _L, unsigned MIN_MATCH, int io_accelerator)
  {
    h = NULL;  errcode = ERROR_MEMORY;  L = _L;
    slices_in_block = sizeof(entry)*CHAR_BIT/BITS;
    slice_size      = L/slices_in_block;                               // to do: 8/16-byte entry (считывать в check по одному байту из h)
    check_slices    = int((MIN_MATCH-L)/slice_size) - io_accelerator;  // if less that this amount of slices around match has the same hashes, then we are sure that match can't be extended to MIN_MATCH size
    if (io_accelerator<0 || check_slices<=0)
         memreq = 0;                                                   // no need in SliceHash since each potential match is almost guaranteed to have MIN_MATCH matched bytes
    else memreq = filesize/L * sizeof(entry);                          // one `entry` per L input bytes
  }

  // Actual memory allocation (should be performed after allocation of more frequently accessed arrays of the HashTable)
  void alloc (LPType LargePageMode)
  {
    if (memreq == 0)   {errcode = NO_ERRORS; return;}
    h        =  (entry*) BigAlloc (memreq, LargePageMode);
    errcode  =  (h==NULL? ERROR_MEMORY : NO_ERRORS);
  }
  ~SliceHash()      {BigFree(h);}

  // Hash of provided buffer
  entry hash (void *ptr, int size)
  {
    uint32 hash = 111222341u;
    for (BYTE *p = (BYTE*)ptr;  (BYTE*)p < (BYTE*)ptr+size;  p++)
      hash  =  (hash*123456791u) + *p;
    return (hash*123456791u) >> (sizeof(uint32)*CHAR_BIT-BITS);
  }

  // Fill h[] with hashes of slices of each chunk in the buf
  void prepare_buffer (Offset offset, char *buf, int size)
  {
    if (h==NULL) return;
    Chunk curchunk = offset/L;
    for (char *p = buf;  p < buf+size;  )
    {
      entry checksum = 0;
      for (int i=0;  i<slices_in_block;  i++, p+=slice_size)
        checksum  +=  hash(p,slice_size) << (i*BITS);
      h[curchunk++] = checksum;
    }
  }

  // Return TRUE if match MAY BE large enough, FALSE - if that's absolutely impossible
  bool check (Chunk chunk, void *p, int i, int block_size)
  {
    if (h==NULL) return true;
    if (i<L || block_size-i<2*L)   // not enough bytes around chunk in the buffer to check them against saved hashes
      return true;
    entry checksum = h[chunk+1];  NUMBER j,k;
    for (j=0; ; j++)
    {
      if (j==check_slices)
        return true;
      if (((checksum>>(j*BITS)) & ONES)  !=  hash ((char*)p+L+j*slice_size, slice_size))
        break;
    }
    checksum = h[chunk-1];
    for (k=0; ; k++)
    {
      if (k+j==check_slices)
        return true;
      if (((checksum>>((slices_in_block-(k+1))*BITS)) & ONES)  !=  hash ((char*)p-(k+1)*slice_size, slice_size))
        break;
    }
    return false;
  }
};


// Match search engine
struct HashTable
{
  bool ROUND_MATCHES;
  bool COMPARE_DIGESTS;
  bool PRECOMPUTE_DIGESTS;
  bool CONTENT_DEFINED_CHUNKING;
  int _errcode;
  size_t L;
  MMAP_FILE &mmap_infile;
  Offset filesize;
  Offset total_chunks;
  Chunk  curchunk, chunknum_mask, hash_mask;
  Offset hs;
  size_t hashsize, hashsize1, hash_shift;
  Chunk           *chunkarr;
  StoredHashValue *hasharr;
  Offset          *startarr;
  Digest          *digestarr;
  SliceHash        slicehash;
  VDigest          MainDigest, PrepDigest;

  // bitarr[] used for fast probing of hash values - it helps to detect whether we ever seen such hash value before
  size_t  bitarrsize;
  size_t  bitshift;
  BYTE   *bitarr;

  HashTable (bool _ROUND_MATCHES, bool _COMPARE_DIGESTS, bool _PRECOMPUTE_DIGESTS, bool INMEM_COMPRESSION, bool _CONTENT_DEFINED_CHUNKING, unsigned _L, unsigned MIN_MATCH, int io_accelerator, unsigned BITARR_ACCELERATOR, MMAP_FILE &_mmap_infile, Offset _filesize, LPType LargePageMode)
    : mmap_infile(_mmap_infile), slicehash(_filesize,_L,MIN_MATCH,io_accelerator)
  {
    _errcode = ERROR_MEMORY;
    ROUND_MATCHES = _ROUND_MATCHES;  COMPARE_DIGESTS = _COMPARE_DIGESTS;  PRECOMPUTE_DIGESTS = _PRECOMPUTE_DIGESTS;  CONTENT_DEFINED_CHUNKING = _CONTENT_DEFINED_CHUNKING;
    L = _L;  filesize = mymax(_filesize,L);  curchunk = 0;  bitarr = NULL;  chunkarr = NULL;  hasharr = NULL;  startarr = NULL;  digestarr = NULL;
    if (INMEM_COMPRESSION)  {_errcode = NO_ERRORS; hs=total_chunks=bitarrsize=0; slicehash.alloc(LargePageMode); return;}
    MainDigest.init();  PrepDigest = MainDigest;  // we need two equal digests since they are used in 2 threads and have internal state modified due hashing
    total_chunks  =  filesize/L;  if (CONTENT_DEFINED_CHUNKING)  total_chunks += total_chunks/(total_chunks>1024?10:1);  // In the CONTENT_DEFINED_CHUNKING mode, chunks may have any size, so we alloc 10% extra space
    chunknum_mask = roundup_to_power_of(total_chunks+2,2)-1;  hash_mask = ~chunknum_mask;   // Masks for cnunk number and hash bits in the chunkarr[] item
    hs = roundup_to_power_of (min_hash_size(total_chunks), 2);
    if (hs > size_t(-1)  ||  total_chunks > MAX_CHUNK-2)  return;
    hashsize = hs,  hashsize1 = hashsize-1,  hash_shift = sizeof(HashValue)*CHAR_BIT - lb(hashsize);
    bitarrsize = (BITARR_ACCELERATOR==0 || CONTENT_DEFINED_CHUNKING)
                   ? 0 : roundup_to_power_of (mymax(total_chunks/CHAR_BIT * BITARR_ACCELERATOR, 2), 2);   // bit array checking works fine until 1/8 of bitarr[] gets filled
    bitshift = sizeof(HashValue)*CHAR_BIT - lb(bitarrsize);    // bitarrsize should be >=2, otherwise hash>>bitshift == hash>>64 == hash>>0 and indexing panics

    // Allocate arrays starting with the most frequently accessed (to increase their chances to become allocated using large pages)
                                     bitarr    = (BYTE*)            BigAllocZero (bitarrsize                            , LargePageMode);    if (!bitarr && bitarrsize!=0) return;
                                     chunkarr  = (Chunk*)           BigAllocZero (hashsize     * sizeof(Chunk)          , LargePageMode);    if (!chunkarr)  return;
    if (!CONTENT_DEFINED_CHUNKING)  {hasharr   = (StoredHashValue*) BigAlloc     (total_chunks * sizeof(StoredHashValue), LargePageMode);    if (!hasharr)   return;}
                                     slicehash.alloc(LargePageMode);
    if (CONTENT_DEFINED_CHUNKING)   {startarr  = (Offset*)          BigAlloc     (total_chunks * sizeof(Offset)         , LargePageMode);    if (!startarr)  return;}
    if (COMPARE_DIGESTS)            {digestarr = (Digest*)          BigAlloc     (total_chunks * sizeof(Digest)         , LargePageMode);    if (!digestarr) return;}

    if (NOT_FOUND!=0)  {fprintf(stderr, "\nHashTable::HashTable() error: NOT_FOUND!=0\n");  abort();}
    _errcode = NO_ERRORS;
  }
  ~HashTable() {BigFree(digestarr); BigFree(startarr); BigFree(hasharr); BigFree(chunkarr); BigFree(bitarr);}

  // Return errcode if any
  int errcode()  {return _errcode!=NO_ERRORS? _errcode : slicehash.errcode;}

  // How much memory required for hash tables with given file and compression method settings
  Offset memreq() {return hs * sizeof(*chunkarr)
                        + total_chunks * ((CONTENT_DEFINED_CHUNKING? sizeof(*startarr) : sizeof(*hasharr)) + (COMPARE_DIGESTS? sizeof(*digestarr) : 0))
                        + bitarrsize
                        + slicehash.memreq;}

  // Performed once for each block read
  void prepare_buffer (Offset offset, char *buf, int size)
  {
    if (PRECOMPUTE_DIGESTS) {                                              // Save chunk digests for secondary, reliable match checking
      Chunk curchunk = offset/L;
      for (char *p = buf;  (buf+size)-p >= L;  p += L)
        PrepDigest.compute (p, L, &digestarr[curchunk++]);
    }
    slicehash.prepare_buffer (offset, buf, size);
  }


  // A quick first probe using bitarr[]
  template <unsigned ACCELERATOR>  void prefetch_check_match_possibility (HashValue hash)  {if    (ACCELERATOR!=0)  prefetch(bitarr[hash>>bitshift]);}
  template <unsigned ACCELERATOR>  bool check_match_possibility          (HashValue hash)  {return ACCELERATOR!=0?          (bitarr[hash>>bitshift]  &  (1<<(size_t(hash)&(CHAR_BIT-1)))) : true;}
  template <unsigned ACCELERATOR>  void mark_match_possibility           (HashValue hash)  {if    (ACCELERATOR!=0)           bitarr[hash>>bitshift]  |=  1<<(size_t(hash)&(CHAR_BIT-1));}


#define stored_hash(hash2)            ((hash2)>>(CHAR_BIT*(sizeof(BigHash)-sizeof(StoredHashValue))))   /* value saved in hasharr[] */
#define index_hash(hash2)             (hash2)                                                           /* value used to index chunkarr[] */

  // Run add_hash0/prefetch_match0/find_match0 with index/stored values deduced in the SAME way from hash2
  Chunk add_hash (void *p, int i, int block_size, Chunk curchunk, BigHash hash2, Offset new_offset)
  {
    return add_hash0<false> (p, i, block_size, curchunk, index_hash(hash2), stored_hash(hash2), new_offset);
  }
  void prefetch_match (BigHash hash2)
  {
    return prefetch_match0 (index_hash(hash2));
  }
  Chunk find_match (void *p, int i, int block_size, BigHash hash2, Offset new_offset)
  {
    return find_match0 (p, i, block_size, index_hash(hash2), stored_hash(hash2), new_offset);
  }


#define first_hash_slot(index)        (index)                              /* the first chunkarr[] slot */
#define next_hash_slot(index,h)       ((h)*123456791+((h)>>16)+462782923)  /* jump to the next chunkarr[] slot */
#define hash_index(h)                 ((h)&hashsize1)                      /* compute chunkarr[] index for given hash value h;  we prefer to use lower bits since higher ones may be shared with stored_hash value */

#define chunkarr_value(hash,chunk)    ((Chunk(hash)&hash_mask)+(chunk))    /* combine hash and number of chunk into the one Chunk value for storing in the chunkarr[] */
#define get_hash(value)               ((value)&hash_mask)                  /* get hash from the combined value */
#define get_chunk(value)              ((value)&chunknum_mask)              /* get chunk number from the combined value */

#define speed_opt                     true                                 /* true: don't use slicehash to try >1 match in -m5 */

  // Add chunk pointed by p to hash, returning equivalent previous chunk
  template <bool CDC>
  Chunk add_hash0 (void *p, int i, int block_size, Chunk curchunk, BigHash index, StoredHashValue stored_value, Offset new_offset)
  {
    CDC && pc.find_match++;
    CDC || (hasharr[curchunk] = stored_value);     // save hash of chunk for primary, quick match checking
    if (curchunk == NOT_FOUND)  return NOT_FOUND;  // it's impossible to hash this chunk number since it's used as signal value

    size_t h = first_hash_slot(index);  int limit = MAX_HASH_CHAIN;  Chunk found = NOT_FOUND,  saved_hash = chunkarr_value(index,0);
    for (Chunk value;  (value = chunkarr[hash_index(h)]) != NOT_FOUND  &&  --limit;  )
    {
      // First check a few hash bits stored in unused chunkarr[] item bits
      if (get_hash(value) == saved_hash)
      {
        Chunk chunk = get_chunk(value);
        Offset match_offset  =  new_offset - start(chunk);
        if (match_offset < pc.max_offset)  CDC && pc.check_hasharr++;
        // Replace in hash chunk with the same digest (-m1..-m3) or hash value (-m4/-m5), supposing that it has the same contents
        if (CDC || hasharr[chunk] == stored_value)
        {
          if (match_offset < pc.max_offset)  CDC && pc.hash_found++;                                        // reuse chunkarr[] item only when...
          if (!COMPARE_DIGESTS?  (speed_opt || slicehash.check (chunk, p, i, block_size))                   // .. subblocks around has the same 1-bit digests (-m5) or always (-m4)
                              :  (0==memcmp(digestarr[chunk], digestarr[curchunk], sizeof(*digestarr))))    // .. entire block has the same 160-bit digest (-m1..-m3)
          {
            found=chunk; break;
          }
        }
      }
      h++, ((limit&3)==0) && (CDC && pc.find_match_memaccess++, h=next_hash_slot(index,h));  // compute next hash slot
    }
    chunkarr[hash_index(h)] = chunkarr_value(index,curchunk);
    return found;
  }

  // Prefetch chunkarr[] element for the find_match0()
  void prefetch_match0 (BigHash index)
  {
    size_t h = first_hash_slot(index);
    prefetch(chunkarr[hash_index(h)]);
  }

  // Find previous L-byte chunk with the same contents
  Chunk find_match0 (void *p, int i, int block_size, BigHash index, StoredHashValue stored_value, Offset new_offset)
  {
    pc.find_match++;
    size_t h = first_hash_slot(index);  int limit = MAX_HASH_CHAIN;  Chunk saved_hash = chunkarr_value(index,0);
    for (Chunk value;  (value = chunkarr[hash_index(h)]) != NOT_FOUND  &&  --limit;  )
    {
      // First check a few hash bits stored in unused chunkarr[] item bits
      if (get_hash(value) == saved_hash)
      {
        Chunk chunk = get_chunk(value);
        Offset match_offset  =  new_offset - Offset(chunk)*L;
        if (match_offset < pc.max_offset)  pc.check_hasharr++;
        // If hash value is the same...
        if (hasharr[chunk] == stored_value)
        {
          if (match_offset < pc.max_offset)  pc.hash_found++;
          if (!COMPARE_DIGESTS)
          {
            // ... we either suppose that chunks are the same (for -m4), check 1-bit digests of subchunks around (for -m5) ...
            if (slicehash.check (chunk, p, i, block_size))
              return chunk;
            else if (speed_opt)
              return NOT_FOUND;
          }
          else
          {
            // ... or compare 160-bit chunk digests (for -m3)
            Digest dig;
            MainDigest.compute (p, L, &dig);
            if (0==memcmp(dig, digestarr[chunk], sizeof(dig)))
              return chunk;
          }
        }
      }
      h++, ((limit&3)==0) && (pc.find_match_memaccess++, h=next_hash_slot(index,h));  // compute next hash slot
    }
    return NOT_FOUND;
  }

  // Length of match, in bytes
  unsigned match_len (Chunk start_chunk, char *min_p, char *start_p, char *last_p, Offset offset, char *buf, unsigned *add_len)
  {
    Offset new_offset = offset+(start_p-buf);
    Offset old_offset = Offset(start_chunk)*L;
    if (new_offset-old_offset < pc.max_offset)  pc.check_len++;
    char *p = start_p;  *add_len = 0;

    // Comparing with data before the current block
    if (COMPARE_DIGESTS)
    {
      // -m3: check match by using saved digests of old chunks
      while (p += L, (old_offset += L) < offset)        // Skip checking first chunk since it was already done in find_match()
      {
        if (last_p-p < L)                               // We have no L-byte chunk to digest
          goto stop;

        Digest dig;                                     // Compare two L-byte blocks by comparison of their digests
        MainDigest.compute (p, L, &dig);
        if (0!=memcmp(dig, digestarr[old_offset/L], sizeof(dig)))
          goto stop;
      }
    }
    else if (old_offset < offset)
    { // -m4/-m5: check match by rereading old data from infile

      // First, compare bytes before match start (which is rounded to L-byte chunk boundary)
      int n = mymin (old_offset, mymin(L, start_p-min_p));   // how much bytes we can check
      if (n > 0  &&  !ROUND_MATCHES)
      {
        // Compare n bytes before start_p
        char *old = (char*) alloca(n);
        int len = mmap_infile.read(&old,old,old_offset-n,n), i;
        if (len != n)  goto stop;
        for (i=1;  i <= n  &&  start_p[-i] == old[n-i];  i++);
        *add_len = i-1;
      }

      // Second, compare bytes after match start
      const int BUFSIZE = 4096;
      for (;  old_offset < offset;  old_offset += BUFSIZE)
      {
        char *old, oldbuf[BUFSIZE];                                   // Buffer for old data
        int len = mmap_infile.read(&old,oldbuf,old_offset,BUFSIZE);   // Read old data from file
        if (len != BUFSIZE)  goto stop;                               // If there was any problem reading entire buf
        for (char *q = old;  q < old+len;  p++, q++)
          if (p==last_p  ||  *p != *q)  goto stop;                    // Exit function once we've found end of match
      }
    }
    else if (!ROUND_MATCHES)
    {
      // -m4/-m5: compare bytes (that are present in current block) before match start
      int i, n = mymin (old_offset-offset, mymin(L, start_p-min_p));   // how much bytes we can check
      for (i=1;  i <= n  &&  start_p[-i] == (buf+(old_offset-offset))[-i];  i++);
      *add_len = i-1;
    }

    // Comparing with data in the current block
    for (char *q = buf+(old_offset-offset);
         p < last_p  &&  *p == *q;
         p++,q++);

    stop:  return p-start_p + *add_len;
  }


  // Chunk start position
  Offset start (Chunk chunk) {return CONTENT_DEFINED_CHUNKING? startarr[chunk] : Offset(chunk)*L;}

  // Chunk size in -m1/-m2 mode
  Offset chunksize_CDC (Chunk chunk)  {return startarr[chunk+1] - startarr[chunk];}

  // Индексировать новый блок и вернуть смещение до эквивалентного ему старого (или 0)
  Offset find_match_CDC (Offset offset, void *p, int size, BYTE *vhashes);
};

Offset HashTable::find_match_CDC (Offset offset, void *p, int size, BYTE *vhashes)
{
  // we have space allocated only for total_chunks chunks
  if (++curchunk >= total_chunks)   return 0;
  startarr[curchunk] = offset;

  // compute digest and hashes of the new chunk (160+64+32 unused bits == 2*128)
  if (sizeof(*digestarr)+sizeof(BigHash) > 2*VMAC_TAG_LEN_BYTES)
    {fprintf(stderr, "\nfind_match_CDC hashsize error: %d+%d > 2*%d\n", int(sizeof(*digestarr)), int(sizeof(BigHash)), VMAC_TAG_LEN_BYTES);  abort();}
  memcpy (digestarr+curchunk, vhashes, sizeof(*digestarr));
  BigHash index  =  *(BigHash*) (vhashes + sizeof(*digestarr));

  // найти в хеш-таблице старый блок, эквивалентный новому, и заменить его новым блоком
  Chunk chunk = add_hash0<true> (p, 0, 0, curchunk, index, 0, offset);

  // если найден старый эквивалентный блок, то возвратить расстояние до него
  if (chunk!=NOT_FOUND && chunksize_CDC(chunk)==size) {
    if (offset < pc.max_offset)
      pc.check_len++,
      pc.record_match++,
      pc.total_match_len += size;
    return offset-startarr[chunk];
  } else {
    return 0;
  }
}

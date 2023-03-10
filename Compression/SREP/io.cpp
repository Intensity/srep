// Copyright (C) 2009-2014 Bulat Ziganshin. All rights reserved.
// Mail Bulat.Ziganshin@gmail.com if you have any questions or want to buy a commercial license for the source code.

// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Error handling ***********************************************************************************************************************************
// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Exit on error
void error (int ExitCode, char *ErrmsgFormat...)
{
  va_list argp;
  va_start(argp, ErrmsgFormat);
  fprintf  (stderr, "\n  ERROR! ");
  vfprintf (stderr, ErrmsgFormat, argp);
  fprintf  (stderr, "\n");
  va_end(argp);

  exit(ExitCode);
}

#define checked_file_read(f, buf, size)                                           \
{                                                                                 \
  if (file_read(f, (buf), (size)) != (size))                                      \
  {                                                                               \
    fprintf (stderr, "\n  ERROR! Can't read from input file");                    \
    errcode = ERROR_IO;                                                           \
    goto cleanup;                                                                 \
  }                                                                               \
}                                                                                 \

#define checked_file_write(f, buf, size)                                          \
{                                                                                 \
  if (file_write(f, (buf), (size)) != (size))                                     \
  {                                                                               \
    fprintf (stderr, "\n  ERROR! Can't write to output file (disk full?)");       \
    errcode = ERROR_IO;                                                           \
    goto cleanup;                                                                 \
  }                                                                               \
}                                                                                 \



// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Background thread ***********************************************************************************************************************************
// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct BG_COMPRESSION_THREAD : BackgroundThread
{
  static const int BUFFERS = 2;
  unsigned k;
  char *dict;
  STAT *aux_statbuf;
  TIndex *hashtable[BUFFERS];    // Place for saving info about maximum hashes and their indexes
  char *bufptr[BUFFERS];
  char *buf[BUFFERS];
  STAT *statbuf[BUFFERS];
  STAT *stat_end[BUFFERS];
  STAT *header[BUFFERS];
  unsigned len[BUFFERS];
  unsigned stat_size[BUFFERS];
  unsigned outsize[BUFFERS];

  volatile int errcode;
  bool ROUND_MATCHES, COMPARE_DIGESTS, no_writes;
  hash_func_t hash_func;
  void *hash_obj;
  unsigned BASE_LEN, bufsize, header_size;
  Offset filesize;
  Offset dictsize;
  Offset memreqs;
  HashTable& h;
  DictionaryCompressor &inmem;
  MMAP_FILE &infile;
  FILE *fin, *fout, *fstat;
  Event ReadDone, WriteReady, BgThreadFinished;


  BG_COMPRESSION_THREAD (bool _ROUND_MATCHES, bool _COMPARE_DIGESTS, unsigned _BASE_LEN, unsigned dict_min_match, bool _no_writes, hash_func_t _hash_func, void* _hash_obj, Offset _filesize, Offset inmem_dictsize, unsigned _bufsize, unsigned _header_size, HashTable& _h, DictionaryCompressor& _inmem, MMAP_FILE& _infile, FILE* _fin, FILE* _fout, FILE* _fstat, LPType LargePageMode)
    : errcode(NO_ERRORS), k(0), ROUND_MATCHES(_ROUND_MATCHES), COMPARE_DIGESTS(_COMPARE_DIGESTS), BASE_LEN(_BASE_LEN), no_writes(_no_writes), hash_func(_hash_func), hash_obj(_hash_obj), filesize(_filesize), bufsize(_bufsize), header_size(_header_size), h (_h), inmem(_inmem), infile(_infile), fin(_fin), fout(_fout), fstat(_fstat)
  {
    dictsize = roundUp(inmem_dictsize,bufsize) + BUFFERS*bufsize;   // Dictionary size should be divisible by bufsize and has additional BUFFERS*bufsize space reserved for background I/O
    dict = (char*) BigAlloc (dictsize, LargePageMode);

    size_t aux_statbuf_size  =  sizeof(STAT) * (inmem_dictsize==0?  STATS_PER_MATCH(ROUND_MATCHES) : MAX_STATS_PER_BLOCK(bufsize,dict_min_match)+10);
    aux_statbuf = (STAT *) malloc(aux_statbuf_size);   // We need to store only one "fence" match if there is no in-memory compression involved

    size_t hashtable_size =  (inmem_dictsize==0?  1 : sizeof(TIndex) * (bufsize/inmem.L + INMEM_PREFETCH) * 2);   // For every L bytes in the buffer, we need 2 hash table elements
    size_t statbuf_size   =  sizeof(STAT) * (MAX_STATS_PER_BLOCK(bufsize,BASE_LEN) + 10);

    for (int i=0; i<BUFFERS; i++)
    {
      hashtable[i] = (TIndex*) malloc(hashtable_size);
      statbuf  [i] = (STAT*)   malloc(statbuf_size);
      header   [i] = (STAT*)   calloc(header_size,1);
      if (!dict || !aux_statbuf || !hashtable[i] || !statbuf[i] || !header[i])
        {errcode=ERROR_MEMORY; return;}
    }

    memreqs = dictsize + aux_statbuf_size + BUFFERS*(hashtable_size + statbuf_size + header_size);
  }

  Offset memreq()  {return memreqs;}

  void wait()
  {
    BgThreadFinished.Wait();
    for (int i=BUFFERS; --i>=0; )
    {
      free(header[i]);
      free(statbuf[i]);
      free(hashtable[i]);
    }
    free(aux_statbuf);
    BigFree(dict);
  }

  int read (char **_buf, STAT **_statbuf, STAT **_header, TIndex **_hashtable)
  {
    ReadDone.Wait();
    k = (k+1)%BUFFERS;
    *_buf     = bufptr[k];
    *_statbuf = statbuf[k];
    *_header  = header[k];
    *_hashtable = hashtable[k];
    return len[k];
  }

  void write (unsigned _stat_size, STAT *_statend, unsigned _outsize)
  {
    stat_size[k] = _stat_size;
    stat_end[k]  = _statend;
    outsize[k]   = _outsize;
    WriteReady.Signal();
  }


private:   // Background thread code
  void run()
  {
    Offset pos = 0;  TIndex buf_offset = 0;
    for(int i=1, first_block=1;  ;  buf_offset=(buf_offset+bufsize)%dictsize, i=(i+1)%BUFFERS, first_block=0)    // i = 1 0 1 0 1...  first_block = 1 0 0 0...
    {
      // 1. Read input data
      buf[i] = dict + buf_offset;
      len[i] = infile.read (&bufptr[i], buf[i], pos, bufsize, fin);       // mmap
      if (!COMPARE_DIGESTS  &&  infile.mmapped()) {
        len[i] = file_read (fin, buf[i], bufsize);  bufptr[i] = buf[i];   // file_read
      }
      if (filesize-pos < len[i])  {fprintf (stderr, "\n  ERROR! Input file is larger than filesize specified"); errcode=ERROR_IO; ReadDone.Signal(); break;}  // Ensure that we don't read more than `filesize` bytes

      // 2. Perform b/g processing of input data
      if (hash_func)                                                      // Save checksum of every input block for error-checking during decompression
        hash_func (hash_obj, bufptr[i],len[i], header[i]+3);
      h.prepare_buffer (pos, bufptr[i], len[i]);
      inmem.prepare_buffer (hashtable[i], bufptr[i], len[i]);

      // 3. Wait for output data from prev. block and write them
      if (!first_block)
        WriteReady.Wait();                          // Wait for output data from prev. block
      ReadDone.Signal();                            // Allow to use input data
      if (!first_block && !no_writes)
        {if (!save_data((i-1+BUFFERS)%BUFFERS))  goto cleanup;}

      // 4. Stop thread on EOF
      if (len[i]==0) break;
      pos += len[i];
    }
cleanup:
    BgThreadFinished.Signal();
  }

  // Write compressed block, returning TRUE on success
  bool save_data (int k)
  {
    char *in   = bufptr [k],  *inend   = bufptr [k] + len[k];
    STAT *stat = statbuf[k],  *statend = stat_end[k];

    checked_file_write (fout,  header [k], header_size);
    checked_file_write (fstat, statbuf[k], stat_size[k]);

    while (statend-stat >= STATS_PER_MATCH(ROUND_MATCHES))
    {
      // Like in original LZ77, LZ matches and literals are strictly interleaved
      DECODE_LZ_MATCH(stat, false, ROUND_MATCHES, BASE_LEN, 0,  lit_len, LZ_MATCH, lz_match);
      if (lit_len > inend-in)  return false;   // Bad compressed data

      // Save literal data
      checked_file_write (fout, in, lit_len);
      in += lit_len+lz_match.len;
    }

    // Copy literal data up to the block end
    checked_file_write (fout, in, inend-in);
    return true;

cleanup:
    return false;
  }
};

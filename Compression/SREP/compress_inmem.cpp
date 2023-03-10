// Copyright (C) 2009-2014 Bulat Ziganshin. All rights reserved.
// Mail Bulat.Ziganshin@gmail.com if you have any questions or want to buy a commercial license for the source code.

typedef size_t TIndex;                  // Index of dict[] element
const int INMEM_PREFETCH = 100;         // How many cycles ahead prefetch the hasharr[]

// In-memory match search engine
struct DictionaryCompressor
{
  TIndex  L;            // Size of rolling hash AND number of positions among those we are looking for "local maxima"
                        //   (these may be different numbers in other implementations)
  TIndex  MIN_MATCH;    // Minimum length of produced matches
  TIndex  BASE_LEN;     // Minimum match length over all compress() procedures, employed by ENCODE_LZ_MATCH

  TIndex  MAX_DIST;     // Maximum match distance
  Offset  hashsize;     // Hash table size, in bytes

  TIndex *hasharr;      // Hash table
  TIndex  hashmask;     // Hash table index mask

  int     errcode;      // Non-zero if anything gone wrong

  DictionaryCompressor (Offset inmem_dictsize, Offset _hashsize, TIndex _MIN_MATCH, TIndex _L, TIndex _BASE_LEN, LPType LargePageMode)
    : MAX_DIST(inmem_dictsize), MIN_MATCH(_MIN_MATCH), L(_L), BASE_LEN(_BASE_LEN)
  {
    errcode = NO_ERRORS;  hashsize = 0;  hasharr = NULL;
    if (!MAX_DIST)   return;
    hashsize = roundup_to_power_of(_hashsize? _hashsize : min_hash_size(sizeof(*hasharr)*(MAX_DIST/L)), 2);
    hashmask = hashsize/sizeof(*hasharr)-1;
    hasharr  = (TIndex*) BigAllocZero (hashsize, LargePageMode);
    if (!hasharr)   {errcode = ERROR_MEMORY; return;}
  }
  Offset memreq()          {return hashsize;}
  ~DictionaryCompressor()  {BigFree(hasharr);}

  void prepare_buffer (TIndex* hashlist, char *buf, TIndex bufsize);
  void compress (char *dict, TIndex dictsize, char *buf, TIndex bufsize, TIndex *hashptr, unsigned &literal_bytes, STAT *statbuf, STAT *&stat);
};

// Находит адрес начала совпадения, идя назад от *p и *q
static inline char* find_match_start (char* p, char* q, char* start)
{
  while (q>start)   if (*--p != *--q)  return q+1;
  return q;
}

// Находит адрес первого несовпадающего байта, идя вперёд от *p и *q
static inline char* find_match_end (char* p, char* q, char* end)
{
  while (q<end && *p==*q) p++,q++;
  return q;
}

// Prepare buffer for the subsequent compression. Performed once for every block read.
// Stores indexes of L-byte blocks starting at buf[0]..buf[bufsize-L] to the hashptr[]
void DictionaryCompressor::prepare_buffer (TIndex* hashptr, char *buf, TIndex bufsize)
{
  if (!MAX_DIST)   return;
  TIndex num_blocks = bufsize/L;        // Number of *whole* L-byte blocks in the buffer. We need at least two blocks to index anything
  if (num_blocks > 1)
  {
    PolynomialRollingHash<TIndex>  hash (buf, L, PRIME1);
    char* ptr = buf;

    // Split buffer into L-byte blocks and store maximal hash from every block and its position to hashptr[]
    for (TIndex block=1; block<num_blocks; block++)
    {
      TIndex maxhash = hash, maxi = 0;
      for (TIndex i=0; i<L; i++, ptr++)
      {
        if unlikely(hash > maxhash)
          maxhash = hash, maxi = i;
        hash.update (ptr[0], ptr[L]);
      }
      *hashptr++ = maxhash & hashmask;
      *hashptr++ = maxi;
    }
    for (TIndex i=0; i<INMEM_PREFETCH*2; i++)
      *hashptr++ = 0;
  }
}

void DictionaryCompressor::compress (char *dict, TIndex dictsize, char *buf, TIndex bufsize, TIndex *hashptr, unsigned &literal_bytes, STAT *statbuf, STAT *&stat)
{
  literal_bytes = bufsize;                      // literal_bytes are computed as the size of entire buffer minus length of all matches
  stat = statbuf;                               // where to save next found match info
  if (!MAX_DIST)   return;

  TIndex bufstart       = buf-dict;
  TIndex bufend         = bufstart+bufsize;
  TIndex last_match_end = bufstart;             // points to the end of last match written, we shouldn't start new match before it
  TIndex DataStart      = (bufstart + dictsize - MAX_DIST) % dictsize;   // first byte that may be included in match because its data was not yet overwritten by the b/g read cycle

  // ОСНОВНОЙ ЦИКЛ, НАХОДЯЩИЙ ПОВТОРЯЮЩИЕСЯ СТРОКИ ВО ВХОДНЫХ ДАННЫХ
  for (TIndex last_i=bufstart; last_i+2*L<=bufend; last_i+=L)
  {
    prefetch(hasharr[hashptr[INMEM_PREFETCH*2]]);   // Prefetch the hasharr[] by INMEM_PREFETCH cycles ahead

    // Проверяем совпадение в лучшем на следующие L байт блоке тоже длины L
    TIndex hash = *hashptr++;                   // Считываем хеш и адрес этого блока, уже найденные в prepare_buffer()
    TIndex i    = last_i + (*hashptr++);
    if (i >= last_match_end)                    // Проверяем совпадение только если предыдущее найденное совпадение уже кончилось
    {
      TIndex match = hasharr[hash];
      if (match)
      {
        Offset match_distance  =  match<i? i-match : dictsize-match+i;
        if (match_distance > MAX_DIST)  goto no_match;
        // Возможно 6 конфигураций взаимного порядка DataStart, match и i. Первые три из них уже отсечены проверкой match_distance.
        // В оставшихся трёх конфигурациях важно проследить, чтобы ни match, ни i в процессе сравнения не вышли за область актуальных данных.
        // Для i это сделать просто: last_match_end<=i<bufend.
        // Для match ограничение: LowBound_for_match<=match<dictsize,
        // где LowBound_for_match  =  match>=DataStart? DataStart : 0
        // и соответственно...
        // Наименьшее/наибольшее значение, которое может принимать при поиске индекс, базирующийся на i,
        // чтобы индекс, базирующийся на match, не вышел за пределы буфера и не заглянул в будущие данные
        TIndex LowBound  = match>=DataStart? (match-DataStart>i? 0 : i-(match-DataStart)) : i-match;
        TIndex HighBound = match<i? dictsize : dictsize-match+i;
        // Найдём реальные начало и конец совпадения, сравнивая вперёд и назад от dict[i] <=> dict[match]
        // i ограничено снизу и сверху значениями last_match_end и bufend, соответственно
        TIndex start = find_match_start (dict+match, dict+i, dict+mymax(last_match_end,LowBound)) - dict;
        TIndex end   = find_match_end   (dict+match, dict+i, dict+mymin(bufend,HighBound)) - dict;
        // start и end - границы совпадения вокруг i, match_len - его длина, lit_len - расстояние от конца предыдущего матча до начала этого
        TIndex match_len = end-start,  lit_len = start-last_match_end;
        if (match_len >= MIN_MATCH)
        {
          // Совпадение найдено! Запишем информацию о нём в выходные буфера
          ENCODE_LZ_MATCH(stat,false,BASE_LEN, lit_len,match_distance,match_len);
          // Запомнить позицию конца найденного совпадения и вывести отладочную статистику
          debug ((match_cnt++, matches+=match_len));
          debug (verbose>1 && printf ("Match %d %d %d  (lit %d)\n", -match_distance, start, match_len, lit_len));
          literal_bytes -= match_len;  last_match_end=end;
        }
      }
    }
no_match:
    hasharr[hash] = i;         // Заносим в хеш-таблицу этот L-байтный блок
  }
}

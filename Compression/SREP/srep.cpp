// Copyright (C) 2009-2014 Bulat Ziganshin. All rights reserved.
// Mail Bulat.Ziganshin@gmail.com if you have any questions or want to buy a commercial license for the source code.

char *program_version     = "SREP 3.93a beta", *program_date = "October 11, 2014";
char *program_description = "huge-dictionary LZ77 preprocessor   (c) Bulat.Ziganshin@gmail.com";
char *program_homepage    = "http://freearc.org/research/SREP39.aspx";

#include <algorithm>
#include <set>
#include <stack>
#include <vector>
#include <malloc.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>

#include "Common.h"
#include "Compression.h"
#include "MultiThreading.h"
#include "MultiThreading.cpp"

// Constants defining compressed file format
const uint SREP_SIGNATURE = 0x50455253;
const uint SREP_FORMAT_VERSION1 = 1;
const uint SREP_FORMAT_VERSION2 = 2;
const uint SREP_FORMAT_VERSION3 = 3;
const uint SREP_FORMAT_VERSION4 = 4;
const uint SREP_FOOTER_VERSION1 = 1;
enum SREP_METHOD {SREP_METHOD0=0, SREP_METHOD1, SREP_METHOD2, SREP_METHOD3, SREP_METHOD4, SREP_METHOD5,
                  SREP_METHOD_FIRST=SREP_METHOD0, SREP_METHOD_LAST=SREP_METHOD5};
typedef uint32 STAT;
const int STAT_BITS=sizeof(STAT)*CHAR_BIT, ARCHIVE_HEADER_SIZE=4, BLOCK_HEADER_SIZE=3, MAX_HEADER_SIZE=4, MAX_HASH_SIZE=256;
enum COMMAND_MODE {COMPRESSION, DECOMPRESSION, INFORMATION};
const char* SREP_EXT = ".srep";

// Compression algorithms constants and defaults
const int MINIMAL_MIN_MATCH = 16;       // minimum match length that sometimes allows to reduce file using the match
const int DEFAULT_MIN_MATCH = 32;       // minimum match length that usually produces smallest compressed file (don't taking into account further compression)

// Program exit codes
enum { NO_ERRORS         = 0
     , WARNINGS          = 1
     , ERROR_CMDLINE     = 2
     , ERROR_IO          = 3
     , ERROR_COMPRESSION = 4
     , ERROR_MEMORY      = 5
     };

typedef uint64 Offset;               // Filesize or position inside file


// Performance counters printed by -pc option - useful for further program optimization
static struct {Offset max_offset, find_match, find_match_memaccess, check_hasharr, hash_found, check_len, record_match, total_match_len;} pc;

void error (int ExitCode, char *ErrmsgFormat...);   // Exit on error


#if defined(_M_X64) || defined(_M_AMD64) || defined(__x86_64__)
#define _32_or_64(_32,_64) (_64)
#define _32_only(_32)      (void(0))
typedef size_t NUMBER;               // best choice for loop index variables on most 64-bit compilers
#else
#define _32_or_64(_32,_64) (_32)
#define _32_only(_32)      (_32)
typedef int NUMBER;                  // best choice for loop index variables on most 32-bit compilers
#endif

#include "hashes.cpp"
#include "hash_table.cpp"


// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Match handling ***********************************************************************************************************************************
// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Structure storing LZ match info
struct LZ_MATCH
{
  LZ_MATCH() : src(Offset(-1)), dest(Offset(-1)), len(STAT(-1)) {}
  Offset src, dest;  // LZ match source & destination absolute positions in file
  STAT   len;        // Match length
};

// Compare LZ matches by source position (for lz_matches[])
bool order_by_LZ_match_src (const LZ_MATCH &left, const LZ_MATCH &right)
{
  return (left.src < right.src);
}

// Compare LZ matches by destination position (for lz_matches_by_dest[])
bool order_by_LZ_match_dest (const LZ_MATCH &left, const LZ_MATCH &right)
{
  return (left.dest < right.dest);
}


// Maximum number of STAT values per compressed block. For every L input bytes, we can write up to 4 STAT values to statbuf
#define MAX_STATS_PER_BLOCK(block_size, L)  (((block_size)/(L)+1)*4)

// FUTURE_LZ needs more space because matches are moved to their source blocks
// So we just alloc block_size bytes
#define FUTURELZ_MAX_STATS_PER_BLOCK(block_size)  ((block_size)/sizeof(STAT))

// Number of STAT values used to encode one LZ match
#define STATS_PER_MATCH(ROUND_MATCHES) (ROUND_MATCHES? 3:4)

// Encode one LZ record to stat[]
#define ENCODE_LZ_MATCH(stat, ROUND_MATCHES, L,  lit_len, lz_match_offset, lz_match_len)                                                             \
  unsigned L1 = (ROUND_MATCHES? L : 1);                                           /* lz_match_len should be divisible by L in -m3 mode */            \
  *stat++ = (lit_len);                                                                                                                               \
  *stat++ = (lz_match_offset)/L1;                                                                                                                    \
  if (!ROUND_MATCHES)  *stat++ = ((lz_match_offset)/L1) >> STAT_BITS;                                                                                \
  if ((lz_match_len) < L)   error (ERROR_COMPRESSION, "ENCODE_LZ_MATCH: match len too small: %d < %d", (lz_match_len), L);                           \
  *stat++ = ((lz_match_len)-L)/L1;

// Decode one LZ record from stat[]
#define DECODE_LZ_MATCH(stat, FUTURE_LZ, ROUND_MATCHES, L, basic_pos,  lit_len, LZ_MATCH_TYPE, lz_match)                                             \
  unsigned L1              = (ROUND_MATCHES? L : 1);                              /* lz_match_len should be divisible by L in -m3 mode */            \
  unsigned lit_len         = *stat++;                                             /* length of literal (copied from in[]) */                         \
  Offset   lz_match_offset = *stat++;                                             /* LZ.dest-LZ.src (divided by L when ROUND_MATCHES==true) */       \
  if (!ROUND_MATCHES)         lz_match_offset += Offset(*stat++) << STAT_BITS;    /* High word of lz_match_offset */                                 \
                              lz_match_offset *= L1;                                                                                                 \
  LZ_MATCH_TYPE lz_match;                                                                                                                            \
                lz_match.len = (*stat++)*L1 + L;                                                                                                     \
  if (!FUTURE_LZ) {                                                                                                                                  \
           lz_match.dest   = (basic_pos) + lit_len;                                                                                                  \
           lz_match.src    = lz_match.dest/L1*L1 - lz_match_offset;                                                                                  \
  } else {                                                                                                                                           \
           lz_match.src    = (basic_pos) + lit_len;                                                                                                  \
           lz_match.dest   = lz_match.src + lz_match_offset;                                                                                         \
  }


// Копирует данные из буфера в буфер, идя в порядке возрастания адресов
// (это важно, поскольку буфера могут пересекаться и в этом случае нужно
// размножить существующие данные)
void memcpy_lz_match (void* _dest, void* _src, unsigned len)
{
  if (len) {
    char *dest = (char*)_dest,  *src = (char*)_src;
    do { *dest++ = *src++;
    } while (--len);
  }
}


// Include compression algorithms
#include "compress_inmem.cpp"
#include "compress_cdc.cpp"
#include "compress.cpp"

// Include decompression algorithms
#include "decompress.cpp"

// Include background I/O routines
#include "io.cpp"


// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Main *********************************************************************************************************************************************
// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Structure describing one compressed block
struct COMPRESSED_BLOCK
{
  COMPRESSED_BLOCK *next;  // Next block in chain
  Offset start, end;       // First and next-after-last byte of the block
  unsigned size;           // Bytes in uncompressed block
  STAT *header;            // Block header data
  STAT *statbuf, *statend; // LZ matches in the block
};

// Print decompression RAM and match stats
void print_info (const char *prefix_str, Offset max_ram, unsigned maximum_save, Offset stat_size, bool ROUND_MATCHES, Offset filesize)
{
  char temp1[100], temp2[100], with_maximum_save_str[100], maximum_save_str[100];
  showMem (maximum_save, maximum_save_str, false);
  sprintf (with_maximum_save_str, (maximum_save != unsigned(-1)? " with -m%s":""), maximum_save_str);
  fprintf (stderr, "%sDecompression memory%s is %d mb.  %s matches = %s bytes = %.2lf%% of file",
                   prefix_str, with_maximum_save_str, int((max_ram+mb-1)/mb),
                   show3(stat_size/(sizeof(STAT)*STATS_PER_MATCH(ROUND_MATCHES)),temp1), show3(stat_size,temp2), double(stat_size)*100/filesize );
}

// Parse -mem option, examples are: -mem100mb, -mem75%, -mem75p, -mem75%-600mb
int64 parse_mem_option (char *option, int *errcode, char spec)
{
  if (*errcode)  return 0;

  // Parse -mem100mb variant
  int64 mem = parseMem (option, errcode, spec);
  if (*errcode==0)  return mem;
  *errcode=0;

  // Parse XX% part
  int percent = 0;
  while (*option >='0'  &&  *option <='9')
    percent = percent*10 + (*option++ - '0');
  if (*option!='%' && *option!='p')  {*errcode=1; return 0;}
  option++;

  // Parse XXmb part
  if      (*option == '\0')   {mem = 0;}                                        // -mem75% variant
  else if (*option++ != '-')  {*errcode=1; return 0;}                           // illegal option
  else                        {mem = parseMem (option, errcode, spec);}         // -mem75%-600mb variant
  return percent*(GetPhysicalMemory()/100) - mem;
}

static void clear_window_title()
{
  Taskbar_Done();
  EnvResetConsoleTitle();
}

void signal_handler(int)
{
  clear_window_title();
  error (ERROR_IO, "^Break pressed");
}


int main (int argc, char **argv)
{
  COMMAND_MODE cmdmode = COMPRESSION;
  SREP_METHOD method = SREP_METHOD3;
  const int DEFAULT_ACCEL = 4;
  Offset filesize = Offset(25)*gb;
  const Offset DEFAULT_DICTSIZE = Offset(512)*mb;
  Offset dictsize = 0,  dict_hashsize = 0;
  double GlobalTime0 = GetGlobalTime();
  unsigned L=0, min_match=0, dict_chunk=0, dict_min_match=0, maximum_save=unsigned(-1), accel=9000, ACCELERATOR=9000, vm_block=8*mb, bufsize=8*mb, NumThreads=0;
  bool INDEX_LZ=true, FUTURE_LZ=false, IO_LZ=false, use_mmap=false, delete_input_files=false, print_pc=false;
  char *index_file="",  *tempfile=NULL,  *DEFAULT_TEMPFILE="srep-data.tmp",  *vmfile_name="srep-virtual-memory.tmp",  *option_s="+";
  int errcode=0, warnings=0, verbosity=2, io_accelerator=1;      LPType LargePageMode=TRY;    char temp1[100];
  struct hash_descriptor *selected_hash = hash_by_name(DEFAULT_HASH, errcode);
  int64 vm_mem = parse_mem_option ("75%", &errcode, 'm');         if (vm_mem > 1536*mb)    _32_only(vm_mem = 1536*mb);
  setbuf(stderr,NULL);    // Disable buffering even if stderr is redirected to file/pipe
  if (errcode)
    error (ERROR_CMDLINE, "Internal error: incorrect default settings");

  //*********************************************************************************************************
  /// PARSE CMDLINE
  //*********************************************************************************************************

  char **filenames = argv,  **next_filename = argv+1;
  while(argv[1])
  {
    char cur_option[1000] = "";
    if (strequ(argv[1],"-d")) {
      cmdmode = DECOMPRESSION;
    } else if (strequ(argv[1],"-i")) {
      cmdmode = INFORMATION;
    } else if (strequ(argv[1],"-delete")) {
      delete_input_files = true;
    } else if (strequ(argv[1],"-mmap")) {
      use_mmap = true;
    } else if (strequ(argv[1],"-nommap")) {
      use_mmap = false;
    } else if (strequ(argv[1],"-s")  ||  strequ(argv[1],"-s-") ||  strequ(argv[1],"-s+")  ||  (start_with(argv[1],"-s") && (strchr(argv[1],'.')||strchr(argv[1],'e')))) {
      option_s = argv[1]+2;
    } else if (start_with(argv[1],"-m")  &&  (isdigit(argv[1][2]) || argv[1][2]=='x')) {
      SREP_METHOD new_method  =  (argv[1][2]=='x'?  SREP_METHOD_LAST  :  SREP_METHOD(argv[1][2]-'0'));
      errcode  =  (new_method<SREP_METHOD_FIRST || new_method>SREP_METHOD_LAST);
      if (!errcode)
      {
        if      (strequ(argv[1]+3, ""))   INDEX_LZ=true,  FUTURE_LZ=false, IO_LZ=false;
        else if (strequ(argv[1]+3, "f"))  INDEX_LZ=false, FUTURE_LZ=true,  IO_LZ=false;
        else if (strequ(argv[1]+3, "o"))  INDEX_LZ=false, FUTURE_LZ=false, IO_LZ=true;
        else                              errcode=1;
        if (!errcode)  method = new_method;
      }
      // If -m... wasn't recognized as the method option, last chance is to recognize it as the maximum save option
      if (errcode)  {errcode = 0;  maximum_save = parseMem (argv[1]+2, &errcode, 'b');}
    } else if (strequ(argv[1],"-f")) {
      INDEX_LZ=false, FUTURE_LZ=true, IO_LZ=false;
    } else if (strequ(argv[1],"-a-")) {
      accel = 0;
    } else if (start_with(argv[1],"-a")  &&  isdigit(argv[1][2])) {
      char* endptr;
      accel        =  strtol (argv[1]+2, &endptr, 0);
      ACCELERATOR  =  (*endptr == '/'?  strtol (endptr+1, &endptr, 0)  :  9000);
      if (*endptr != '\0')
        errcode = 1;
    } else if (strequ(argv[1],"-ia-")) {
        io_accelerator = -1;
    } else if (strequ(argv[1],"-ia+")) {
        io_accelerator = 1;
    } else if (strequ(argv[1],"-slp")) {
        LargePageMode = TRY;
    } else if (strequ(argv[1],"-slp-")) {
        LargePageMode = DISABLE;
    } else if (strequ(argv[1],"-slp+")) {
        LargePageMode = FORCE;
    } else if (strequ(argv[1],"-hash-") || strequ(argv[1],"-nomd5")) {
      selected_hash = hash_by_name("", errcode);
    } else if (start_with(argv[1],"-hash=")) {
      selected_hash = hash_by_name(argv[1]+6, errcode);
    } else if (strequ(argv[1],"-v")) {
      verbosity = 1;
    } else if (start_with(argv[1],"-v")) {
      verbosity = parseInt (argv[1]+2, &errcode);
    } else if (start_with(argv[1],"-pc")) {
      print_pc = true;
      pc.max_offset  =  argv[1][3]? parseMem64 (argv[1]+3, &errcode, 'm') : Offset(-1);
    } else if (start_with(argv[1],"-index=")) {
      index_file = argv[1]+7;
    } else if (start_with(argv[1],"-temp=")) {
      tempfile = argv[1]+6;
    } else if (start_with(argv[1],"-vmfile=")) {
      vmfile_name = argv[1]+8;
    } else if (start_with(argv[1],"-vmblock=")) {
      vm_block = parseMem (argv[1]+9, &errcode, 'm');
    } else if (start_with(argv[1],"-mem")) {
      vm_mem = parse_mem_option (argv[1]+4, &errcode, 'm');
    } else if (start_with(argv[1],"-l")) {
      min_match = parseMem (argv[1]+2, &errcode, 'b');
    } else if (start_with(argv[1],"-c")) {
      L = parseMem (argv[1]+2, &errcode, 'b');
    } else if (start_with(argv[1],"-s")) {
      filesize = parseMem64 (argv[1]+2, &errcode, 'b');
    } else if (start_with(argv[1],"-b")) {
      bufsize = parseMem (argv[1]+2, &errcode, 'm');
    } else if (strequ(argv[1],"-d-")) {
      dictsize = 0;
    } else if (strequ(argv[1],"-d+")) {
      dictsize = DEFAULT_DICTSIZE;
    } else if (start_with(argv[1],"-d")) {
      char* param[100];
      int params = split (argv[1]+2, ':', param, 100);
      for (int i=0; i<params && !errcode; i++)
      {
        switch (*param[i])
        {
          case 'a':                    parseInt (param[i]+1, &errcode);       break;  // Ignore -da option for a while
          case 'c':   dict_chunk     = parseMem (param[i]+1, &errcode, 'b');  break;
          case 'l':   dict_min_match = parseMem (param[i]+1, &errcode, 'b');  break;
          case 'd':   dictsize       = parse_mem_option (param[i]+1, &errcode, 'm');  break;
          case 'h':   dict_hashsize  = parse_mem_option (param[i]+1, &errcode, 'm');  break;
          default:    dictsize       = parse_mem_option (param[i],   &errcode, 'm');  break;
        }
        if (errcode)  sprintf(cur_option, "-d%s", param[i]);
      }
    } else if (start_with(argv[1],"-t")) {
      NumThreads = parseInt (argv[1]+2, &errcode);
    } else if (start_with(argv[1],"-rem")) {
      // Command-line remark
    } else if (strequ(argv[1],"--")) {
      argv++;
      do {*next_filename++ = argv[1];} while (*++argv);    // no more options - copy remaining filenames
      break;
    } else if (start_with(argv[1],"-")  &&  !strequ(argv[1],"-")) {
      errcode = 1;
    } else {
      *next_filename++ = argv[1];                          // not an option - copy argv[1] to the filenames list
    }
    if (errcode)
      error (ERROR_CMDLINE, "Invalid option: %s",  (*cur_option? cur_option : argv[1]));
    argv++;
  }
  *next_filename = NULL;
  char *_filenames[] = {"","-","-",NULL};

  // (De)compress from stdin to stdout if no filenames are given, but both stdin and stdout are redirected
  if (filenames[1]==NULL  &&  !isatty(fileno(stdin))  &&  !isatty(fileno(stdout)))
    filenames = _filenames;

  const bool INMEM_COMPRESSION         =  (method == SREP_METHOD0);   // In-memory compression (REP algorithm)
  const bool CONTENT_DEFINED_CHUNKING  =  (SREP_METHOD1<=method && method<=SREP_METHOD2);   // Content-defined-chunking deduplication
  const bool ZPAQ_CDC                  =  (method == SREP_METHOD2);   // ZPAQ algorithm of content-defined chunking
  const bool COMPARE_DIGESTS           =  (method <= SREP_METHOD3);   // Check matches by comparison of their digests, otherwise - check matches by rereading old data
  const bool PRECOMPUTE_DIGESTS        =  (method == SREP_METHOD3);   // Split data into fixed-size blocks and precompute their digests prior to main processing cycle
  const bool ROUND_MATCHES             =  (method == SREP_METHOD3) && (dictsize==0);   // Match lengths are multiplies of L, otherwise - arbitrary value (>= min_match)
  const bool EXHAUSTIVE_SEARCH         =  (method == SREP_METHOD5);   // Check all matches starting at L/2 length in order to find L-byte match
  if (INMEM_COMPRESSION && dictsize==0)   dictsize = DEFAULT_DICTSIZE;
  if (CONTENT_DEFINED_CHUNKING && dictsize)                           // CDC isn't yet compatible with in-memory compression
    error (ERROR_CMDLINE, "Incompatible options: -m%d -d%s", method, showMem64(dictsize,temp1));
  if (!L && !min_match)
    min_match  =  (CONTENT_DEFINED_CHUNKING? 4096 : 512);             // Default -l value
  if (!L) {
    if (CONTENT_DEFINED_CHUNKING)     L=min_match, min_match=0;                                // For -m1/-m2, -lX===-l0 -cX
    else  L  =  (!EXHAUSTIVE_SEARCH?  min_match  :  rounddown_to_power_of(min_match+1,2)/2);   // Only -m5 performs exhaustive search for ALL matches of min_match bytes or longer
  }
  if (!min_match)        min_match = (CONTENT_DEFINED_CHUNKING? DEFAULT_MIN_MATCH : L);
  if (!dict_min_match)   dict_min_match = 512;                // Default -dl value
  if (!dict_chunk)       dict_chunk     = dict_min_match/8;   // For in-memory compression, default chunk size is 1/8 of the minimum match length
  unsigned BASE_LEN  =  mymin (min_match, dict_min_match);    // Guaranteed minimum match length, so lengths in STAT are encoded minus this value
  unsigned FUTURELZ_BASE_LEN  =  (IO_LZ?  BASE_LEN : 0);      // With dictionary-based compression or -m4/-m5, LZ match source may be split between two blocks, resulting in two smaller matches (starting from len==1) with Future-LZ/Index-LZ
  if (L!=roundup_to_power_of(L,2) && !CONTENT_DEFINED_CHUNKING) {
    fprintf (stderr, "Warning: -l parameter should be power of 2, otherwise compressed file may be corrupt\n");
    warnings++;
  }
  if (vm_mem > size_t(-1))    vm_mem = size_t(-1);     // For 32-bit systems (say, 50% of 16gb RAM may be a bit too much). Better, use GetTotalMemoryToAlloc()

  if (filenames[1]==NULL) {
    printf (         "%s: %s\n"
                     "%s    homepage: %s\n"
                     "\n"
                     "Usage: SREP [options] infile [outfile]\n"
                     "   infile/outfile can be specified as \"-\" for stdin/stdout\n"
                     "   \"SREP [options] somefile\" compresses data from somefile to somefile.srep\n"
                     "   \"SREP [options] somefile.srep\" decompresses data back to somefile\n"
                     "   \"SREP [options]\" compresses and \"SREP -d [options]\" decompresses data from stdin to stdout\n"
                     "\n"
                     "Options are:\n"
                     "   -m0: only in-memory compression (REP algorithm)\n"
                     "   -m1: fixed-window content-defined chunking with matches checked by VMAC\n"
                     "   -m2: order-1 content-defined chunking with matches checked by VMAC\n"
                     "   -m3: check matches by VMAC digest (compression memory = 7-8%% of filesize)\n"
                     "   -m4: check matches by rereading old data (compression memory = 3-4%% of filesize)\n"
                     "   -m5/-mx: rereading with byte-accurate matches (compression memory = 7-9%% of filesize)\n"
                     "   -l: minimum LZ match length, default %d\n"
                     "   -c: size of hash chunk, by default as small as required to find all these LZ matches\n"
                     "   -aX[/Y]: alloc X bytes of those Y bits will be set per L input bytes for compression accelerator\n"
                     "            Y=0/1/2/4/8/16/32/64, -a0 is slowest but requires least memory\n"
                     "   -ia-: disable I/O acceleration to reduce memory usage (-m5* only)\n"
                     "   -tN: use N compression threads (only for -m1/-m2)\n"
                     "   -dBYTES: dictionary size for in-memory compression (REP algorithm), default %dmb\n"
                     "   -dhBYTES/-dcN/-dlN: size of hash / size of hash chunk / minimum match length for in-memory compression\n"
                     "\n"
                     "   -m1..-m5: index-LZ - list of matches saved at the end of compressed file\n"
                     "   -m1f..-m5f: future-LZ - decompression dictionary will hold only future matches\n"
                     "   -m1o..-m5o: I/O LZ - output file used as decompression dictionary\n"
                     "   -memBYTES: amount of RAM used by future-LZ/index-LZ decompression (extra goes into VM file)\n"
                     "      -mem75%% AKA -mem75p means \"use no more than 75%% of RAM\" - that's by default\n"
                     "      -mem600mb means itself\n"
                     "      -mem75%%-600mb means \"use no more than 75%% of RAM minus 600 mb\"\n"
                     "   -mBYTES: don't store matches larger than BYTES on future-LZ/index-LZ decompression\n"
                     "\n"
                     "   -d: decompression (for -m0o..m5o requires only 24 mb of memory besides of OS I/O buffers)\n"
                     "   -i: print info about compressed file: srep -i datafile.srep\n"
                     "   -delete: delete source file after successful (de)compression\n"
                     "   -sBYTES: explicitly specify filesize (for compression from stdin), default %dgb\n"
                     "   -bBYTES: change compression block size, default %dmb\n"
                     "   -index=FILENAME: read/write index of compressed data into separate file\n"
                     "   -temp=[FILENAME]: keep uncompressed data in the file in stdin-to-stdout mode, default %s\n"
                     "   -vmfile=FILENAME: temporary file used by Virtual Memory manager, default %s\n"
                     "   -vmblock=BYTES: size of one block in VM temporary file, default %dmb\n"
                     "\n"
                     "   -hash=%s: store hash checksums in every block\n"
                     "   -hash-: don't store/check block checksums\n"
                     "   -mmap: use memory-mapped files for match checking\n"
                     "   -slp[+/-/]: force/disable/try(default) large pages support (2mb/4mb)\n"
                     "   -pc[max_offset]: display performance counters [for matches closer than max_offset]\n"
                     "   -s: save printed stats from overwriting; -s+/-s-/-sX.Y: update stats every X.Y seconds\n"
                     "   -v[0..2]: verbosity level\n"
                     "   -rem...: command-line remark\n",
                     program_version, program_description, program_date, program_homepage,
                     int(dictsize/mb), min_match, int(filesize/gb), int(bufsize/mb), DEFAULT_TEMPFILE,  vmfile_name, int(vm_block/mb), HASH_LIST);
    exit (NO_ERRORS);
  }
  if (cmdmode==INFORMATION && filenames[2]) {
    error (ERROR_CMDLINE, "Too much filenames: %s %s", filenames[1], filenames[2]);
  }
  if (filenames[2] && filenames[3]) {
    error (ERROR_CMDLINE, "Too much filenames: %s %s %s", filenames[1], filenames[2], filenames[3]);
  }

  //*********************************************************************************************************
  /// OPEN INPUT/OUTPUT/TEMPORARY FILES
  //*********************************************************************************************************

  char *finame   = filenames[1];
  char *foutname = (cmdmode==INFORMATION? (char*)NULL_FILENAME : filenames[2]);
  if (!foutname)
  {
    // If second filename isn't provided, then decompress or compress depending on infile extension (.srep or not).
    // Output filename is input filename plus .srep for compression, or minus .srep for decompression.
    foutname = new char [strlen(finame) + strlen(SREP_EXT) + 2];
    strcpy(foutname,finame);
    if (end_with(finame,SREP_EXT)) {
      foutname[strlen(foutname)-strlen(SREP_EXT)] = '\0';
      cmdmode = DECOMPRESSION;
    } else {
      strcat(foutname,SREP_EXT);
    }
  }

  bool single_pass_compression  =  COMPARE_DIGESTS && !FUTURE_LZ;    // -m0..-m3/-m0o..-m3o are the only compression modes having no need to reread input data
  if (cmdmode==COMPRESSION && !single_pass_compression && strequ(finame,"-"))
  {
    if (!tempfile)
      tempfile = DEFAULT_TEMPFILE;
    else if (*tempfile==0)
      error (ERROR_IO, "Reading data to compress from stdin without tempfile isn't supported for this method");
  }
  if (!strequ(finame,"-") && strequ(finame,foutname))
    error (ERROR_IO, "Input and output files should have different names");

  FILE *fin = strequ (finame, "-")? stdin : fopen (finame, "rb");
  if (fin == NULL)  error (ERROR_IO, "Can't open %s for read", finame);
  set_binary_mode (fin);

  FILE *fout = strequ (foutname, "-")? stdout : fopen (foutname, "w+b");
  if (fout == NULL)  error (ERROR_IO, "Can't open %s for write", foutname);
  set_binary_mode (fout);

  FILE *fstat = *index_file? fopen (index_file, cmdmode==COMPRESSION? "wb" : "rb") : (cmdmode==COMPRESSION? fout : fin);
  if (fstat == NULL)  error (ERROR_IO, "Can't open index file %s for write", index_file);

  FILE *ftemp = NULL;

  STAT header[MAX_HEADER_SIZE+MAX_HASH_SIZE];  zeroArray(header);   // header size depends on the *selected_hash properties
  filesize  =  (strequ(finame,"-")? filesize : get_flen(fin));
  Offset origsize = 0,  compsize = 0,  ram = 0,  max_ram = 0;
  // Reduce default accel value for small L
  if (accel==9000)         accel        =  mymin (mymax(L/32,1), DEFAULT_ACCEL);  unsigned BITARR_ACCELERATOR = accel*8;
  // Maximum default acceleration level for main loop is 16; larger -a values only increase bitarr[] size
  if (ACCELERATOR==9000)   ACCELERATOR  =  mymin(accel,16);
  // Required to overwrite previous, longer stats line
  const char *newline = strequ(option_s,"")? "\n":"    \b\b\b\b";
  // Interval in seconds between statistics updates
  double TimeInterval = strequ(option_s,"")? 1e-30 : strequ(option_s,"-")? 1e30 : strequ(option_s,"+")? 0.2 : atof(option_s);
  // Last time/origsize when progress indicator was printed
  double LastGlobalTime = 0;  Offset last_origsize = Offset(-1);
  // Miscellaneous
  void *hash_obj = NULL;  if (NumThreads==0)  NumThreads = GetProcessorsCount();
  Install_signal_handler(signal_handler);

  if (cmdmode==COMPRESSION)
  {
    //*********************************************************************************************************
    /// COMPRESSION
    //*********************************************************************************************************

    const int header_size = sizeof(STAT)*BLOCK_HEADER_SIZE + selected_hash->hash_size;  // compressed block header size
    ftemp  =  (tempfile && *tempfile)? fopen (tempfile, "w+b") : (strequ (finame, "-")? fin : fopen (finame, "rb"));
    if (ftemp == NULL)  error (ERROR_IO, "Can't open tempfile %s for write", tempfile);
    if (tempfile && *tempfile)  use_mmap = false;

    // Seed keyed hash like VMAC with the random data
    void *seed = malloc(selected_hash->hash_seed_size);
    if (selected_hash->new_hash)
    {
      cryptographic_prng (seed, selected_hash->hash_seed_size);
      hash_obj = selected_hash->new_hash (seed, selected_hash->hash_seed_size);
    }

    COMPRESSED_BLOCK *first_block,  **last_block = &first_block;                 // head of linked list of blocks in FUTURE_LZ mode
    Offset lz_matches_count = 0;                                                 // LZ matches found
    size_t total_blocks = 0;  Offset total_stat_size = 0;
    {
      MMAP_FILE  mmap_infile(use_mmap, ftemp, "r", filesize);
      CDC_Global g(CONTENT_DEFINED_CHUNKING, NumThreads);
      HashTable  h(ROUND_MATCHES, COMPARE_DIGESTS, PRECOMPUTE_DIGESTS, INMEM_COMPRESSION, CONTENT_DEFINED_CHUNKING, L, min_match, io_accelerator, BITARR_ACCELERATOR, mmap_infile, filesize, LargePageMode);
      DictionaryCompressor inmem(dictsize, dict_hashsize, dict_min_match, dict_chunk, BASE_LEN, LargePageMode);
      BG_COMPRESSION_THREAD bg_thread(ROUND_MATCHES, COMPARE_DIGESTS, BASE_LEN, dict_min_match, FUTURE_LZ, selected_hash->hash_func, hash_obj, filesize, dictsize, bufsize, header_size, h, inmem, mmap_infile, fin, fout, fstat, LargePageMode);
      double memreq = double(h.memreq()+inmem.memreq()+bg_thread.memreq()) / mb;
      if (g.errcode || h.errcode() || inmem.errcode || bg_thread.errcode)   error (ERROR_MEMORY, "Can't allocate memory: %.0lf mb required (-l64k -a- -ia- options may help)", memreq);
      bg_thread.start();
      if (verbosity > 1)
      {
        char min_match_str[100], L_str[100], l_c_t_str[100], l_c_a_str[100], hashname_str[100], bufsize_str[100];
        char dictsize_str[100], dict_hashsize_str[100], dict_compressor_str[100], dict_min_match_str[100], dict_chunk_str[100];

        showMem (bufsize, bufsize_str);  showMem (dictsize, dictsize_str);  showMem (inmem.hashsize, dict_hashsize_str);
        showMem (min_match, min_match_str, false);  showMem (L, L_str, false);
        showMem (dict_min_match, dict_min_match_str, false);  showMem (dict_chunk, dict_chunk_str, false);

        sprintf (l_c_t_str, " -l%s -c%s -t%d", min_match_str, L_str, NumThreads);
        sprintf (l_c_a_str, " -l%s -c%s -a%d/%d", min_match_str, L_str, accel, ACCELERATOR);
        sprintf (hashname_str, "=%s", selected_hash->hash_name);
        sprintf (dict_compressor_str, " -d%s:h%s:l%s:c%s", dictsize_str, dict_hashsize_str, dict_min_match_str, dict_chunk_str);

        fprintf (stderr, "%s (%s): input size %.0lf mb, memory used %.0lf mb, -m%d%s%s%s%s%s -hash%s -b%s%s\n", program_version, program_date,
                         double(filesize/mb), memreq, method, FUTURE_LZ?"f":(IO_LZ?"o":""),
                         INMEM_COMPRESSION? "" : (CONTENT_DEFINED_CHUNKING? l_c_t_str : l_c_a_str),
                         EXHAUSTIVE_SEARCH? (io_accelerator>0? " -ia+":" -ia-") : "",
                         use_mmap? " -mmap":"",  LargePageMode==FORCE? " -slp+" : (LargePageMode==DISABLE? " -slp-" : ""),
                         strequ(selected_hash->hash_name,"")?"-":hashname_str, bufsize_str, dictsize? dict_compressor_str: "");
      }

      // Write compressed file header
      header[0] = BULAT_ZIGANSHIN_SIGNATURE;
      header[1] = SREP_SIGNATURE;
      header[2] = (INDEX_LZ? SREP_FORMAT_VERSION4 : (FUTURE_LZ? SREP_FORMAT_VERSION3 : (ROUND_MATCHES? SREP_FORMAT_VERSION1 : SREP_FORMAT_VERSION2)))
                  + (selected_hash->hash_num       << 8)
                  + (selected_hash->hash_seed_size << 16)
                  +((selected_hash->hash_size-16)  << 24);
      header[3] = FUTURELZ_BASE_LEN;
      checked_file_write (fout, header, sizeof(STAT)*ARCHIVE_HEADER_SIZE);
      checked_file_write (fout, seed,   selected_hash->hash_seed_size);
      compsize = sizeof(STAT)*ARCHIVE_HEADER_SIZE + selected_hash->hash_seed_size;

#define INDEX_LZ_FOOTER_SIZE (sizeof(STAT)*6)
      if (INDEX_LZ)
        compsize += INDEX_LZ_FOOTER_SIZE;   // accounting for the future write of INDEX_LZ_FOOTER

      double OperationStartGlobalTime = (LastGlobalTime = GetGlobalTime() - GlobalTime0);

      // Compress data by 8mb (bufsize) blocks until EOF
      for(;;)
      {
        // Read next input block (saving its copy to tempfile)
        char *buf;  STAT *statbuf, *stat, *header, *aux_statbuf=bg_thread.aux_statbuf;  TIndex *hashptr;  unsigned literal_bytes;
        int len = bg_thread.read (&buf, &statbuf, &header, &hashptr);   // Read data from file
        if (bg_thread.errcode)  {errcode = bg_thread.errcode; goto cleanup;}
        if (len==0)  goto print_stats;
        if (tempfile && *tempfile) {
          file_seek (ftemp, origsize);
          checked_file_write (ftemp, buf, len);
        }

        // Compress the block
        inmem.compress (bg_thread.dict, bg_thread.dictsize, buf,len, hashptr, literal_bytes,INMEM_COMPRESSION?statbuf:aux_statbuf,stat);
        if (!INMEM_COMPRESSION)
          {ENCODE_LZ_MATCH(stat,ROUND_MATCHES,BASE_LEN, len+1,Offset(BASE_LEN),BASE_LEN);}  // pseudo-match used to limit matches read from the aux_statbuf[]

        if (INMEM_COMPRESSION)
          {}
        else if (CONTENT_DEFINED_CHUNKING)
          compress_CDC (ZPAQ_CDC,L,min_match,origsize,h,g, buf,len,literal_bytes,statbuf,stat);
        else
          switch (ACCELERATOR)
          {
            case  0:  compress< 0>(ROUND_MATCHES,L,min_match,BASE_LEN,origsize,h, buf,len, literal_bytes,aux_statbuf,statbuf,stat); break;
            case  1:  compress< 1>(ROUND_MATCHES,L,min_match,BASE_LEN,origsize,h, buf,len, literal_bytes,aux_statbuf,statbuf,stat); break;
            case  2:  compress< 2>(ROUND_MATCHES,L,min_match,BASE_LEN,origsize,h, buf,len, literal_bytes,aux_statbuf,statbuf,stat); break;
            case  4:  compress< 4>(ROUND_MATCHES,L,min_match,BASE_LEN,origsize,h, buf,len, literal_bytes,aux_statbuf,statbuf,stat); break;
            case  8:  compress< 8>(ROUND_MATCHES,L,min_match,BASE_LEN,origsize,h, buf,len, literal_bytes,aux_statbuf,statbuf,stat); break;
            case 16:  compress<16>(ROUND_MATCHES,L,min_match,BASE_LEN,origsize,h, buf,len, literal_bytes,aux_statbuf,statbuf,stat); break;
            case 32:  compress<32>(ROUND_MATCHES,L,min_match,BASE_LEN,origsize,h, buf,len, literal_bytes,aux_statbuf,statbuf,stat); break;
            case 64:  compress<64>(ROUND_MATCHES,L,min_match,BASE_LEN,origsize,h, buf,len, literal_bytes,aux_statbuf,statbuf,stat); break;
          }

       {// Fill compressed block header
        unsigned stat_size  =  (char*)stat - (char*)statbuf;
        header[0] = literal_bytes;
        header[1] = len;
        header[2] = (INDEX_LZ? 0 : stat_size);

        // Write compressed block to output file(s)
        bg_thread.write (header[2], stat, literal_bytes);
        if (bg_thread.errcode)  {errcode = bg_thread.errcode; goto cleanup;}

        // Store matches in memory
        if (FUTURE_LZ || INDEX_LZ)
        {
          total_blocks++;
          lz_matches_count += (stat - statbuf) / STATS_PER_MATCH(ROUND_MATCHES);

          // Save header[] and statbuf[] to the COMPRESSED_BLOCK struct
          int blocksize = sizeof(COMPRESSED_BLOCK) + header_size + stat_size;
          COMPRESSED_BLOCK *block = (COMPRESSED_BLOCK *) new char[blocksize];

          block->start = origsize;
          block->size  = len;
          block->end   = block->start + block->size;
          block->header  = (STAT*)(block+1);
          block->statbuf = (STAT*)((char*)block->header + header_size);
          block->statend = (STAT*)((char*)block->statbuf + stat_size);
          memcpy(block->header,  header,  header_size);
          memcpy(block->statbuf, statbuf, stat_size);

          // Join COMPRESSED_BLOCK structs into linked list
          *last_block = block;
          last_block = &block->next;

          if (ROUND_MATCHES)
            compsize += stat_size / STATS_PER_MATCH(ROUND_MATCHES);   // Добавить размер одного слова STAT из-за того, что данные собираются с ROUND_MATCHES (по 12 байт), а кодироваться будут без него (по 16 байт)

          if (INDEX_LZ)
            compsize += sizeof(STAT);   // accounting for the future write of statsize_buf[]
        }

        // Update statistics
        total_stat_size += stat_size;
        compsize += literal_bytes + stat_size + header_size;
        origsize += len;}

print_stats:
        if (len==0)  bg_thread.wait();     // Wait until all compressed data are successfully saved to disk
        if (verbosity)
        {
          double GlobalTime = GetGlobalTime()-GlobalTime0;
          if (origsize!=last_origsize  &&  (len==0 || GlobalTime-LastGlobalTime>TimeInterval))
          {
            LastGlobalTime = GlobalTime;  last_origsize = origsize;  double CPUTime = GetCPUTime();
            char temp1[100], temp2[100], temp3[100], temp4[100], temp5[100], temp6[100], temp7[100], counters[200];
            char remains[100], remains0[100], console_title[MY_FILENAME_MAX+100];
            Offset x = pc.check_len-pc.record_match;
            sprintf (counters, "PC %s+%s+%s  %s%s+%s%s.  ",
                             show3(pc.find_match,temp1), show3(pc.find_match_memaccess,temp2), show3(pc.check_hasharr,temp3),
                             show3(pc.record_match,temp4), x?show3(x,temp5,"+"):"", show3(pc.hash_found-pc.check_len,temp6),
                             pc.max_offset<Offset(-1)? show3(pc.total_match_len,temp7,"  "):"");

            int percents = int(double(origsize)*100/filesize);
            int remain = int(round(double(filesize-origsize)/origsize * (GlobalTime - OperationStartGlobalTime)));
            if (remain>=3600)
                 sprintf (remains0, "%02d:%02d:%02d", remain / 3600, (remain % 3600) / 60, remain % 60);
            else sprintf (remains0, "%02d:%02d", remain / 60, remain % 60);

            fprintf (stderr, "\r%d%%: %s -> %s: %.2lf%%.  %sCpu %.0lf mb/s (%.3lf sec), real %.0lf mb/s (%.3lf sec) = %.0lf%%.  Remains %s   %s",
                             percents,  show3(origsize,temp1),  show3(compsize,temp2),  double(compsize)*100/origsize, print_pc? counters:"",
                             origsize/CPUTime/mb, CPUTime, origsize/GlobalTime/mb, GlobalTime, CPUTime/GlobalTime*100, remains0, newline);

            sprintf (console_title, "%d%% %s | Compressing %s", percents, remains0, (strequ (finame, "-")? "from stdin" : finame));
            EnvSetConsoleTitleA (console_title);

            Taskbar_SetProgressValue (origsize, filesize);
          }
        }
        if (len==0) break;
      }

      if (bg_thread.errcode)  {errcode = bg_thread.errcode; goto cleanup;}
    }


    //*********************************************************************************************************
    /// SECOND PASS FOR FUTURE_LZ/INDEX_LZ MODES
    //*********************************************************************************************************

    if (FUTURE_LZ || INDEX_LZ)
    {
      *last_block = NULL;   // Mark end of linked list
      if (verbosity)
        fprintf (stderr, "\nSorting matches...");

      char *buf     = new char[bufsize+1];
      char *outbuf  = new char[bufsize], *out;
      STAT *statbuf = new STAT[FUTURELZ_MAX_STATS_PER_BLOCK(bufsize)], *stat;

      // 1. Fill lz_matches[] with matches from all compressed blocks
      LZ_MATCH *lz_matches = new LZ_MATCH[lz_matches_count+1];          // +1 is for the loop barrier
      int i = 0;                                                        // lz_matches[] index

      for (COMPRESSED_BLOCK *block = first_block;  block;  block = block->next)
      {
        // Copy to lz_matches[] all matches from the block
        Offset block_pos = block->start;                                // current position in the input file
        for (STAT *stat = block->statbuf;  stat < block->statend;  )
        {
          // Copy one LZ match record from stat[] to lz_matches[]
          DECODE_LZ_MATCH(stat, false, ROUND_MATCHES, BASE_LEN, block_pos,  lit_len, LZ_MATCH, lz_match);
          lz_matches[i++]  = lz_match;
          block_pos       += lit_len + lz_match.len;
        }
      }


      // 2. Sort array by absolute position of LZ match source
      std::sort (lz_matches, lz_matches+lz_matches_count, order_by_LZ_match_src);
      lz_matches[lz_matches_count].src = origsize;   // Loop barrier


      // 3. Process input file once again, joining future-LZ matches info with literal data
      file_seek (ftemp, 0);  Offset processed = 0;  total_stat_size = 0;  i = 0;
      STAT *statsize_buf = new STAT[total_blocks],  *statsize_ptr = statsize_buf;  int last_textlen = 0;
      LZ_MATCH_HEAP lz_match_heap;  FUTURE_LZ_MATCH barrier;  barrier.dest = Offset(-1);  lz_match_heap.insert(barrier);
      double OperationStartGlobalTime = (LastGlobalTime = GetGlobalTime() - GlobalTime0);
      if (FUTURE_LZ && verbosity)
        fprintf (stderr, "  Second pass: ");

      for (COMPRESSED_BLOCK *block = first_block;  block;  block = block->next )
      {
        // Calculate how much RAM will be required for decompression.  Part I: remove matches with destination in the current block
        for (LZ_MATCH_ITERATOR lz_match = lz_match_heap.begin();  lz_match->dest < block->end;  lz_match = lz_match_heap.begin())
        {
          ram -= MEMORY_MANAGER::needmem(lz_match->len);
          lz_match_heap.erase(lz_match);
        }

        // Fill stat[] with future-LZ matches whose LZ.src lies in the current block
        stat = statbuf;  Offset block_pos = block->start;
        int saved_i = i;                                                // First match that should be checked in the next block
        for (;  lz_matches[i].src < block->end;  i++)
        {
          if (lz_matches[i].src+lz_matches[i].len <= block->start)      // Skip any matches entirely owned by previous blocks, updating saved_i too
            {saved_i = i; continue;}
          Offset src = mymax (lz_matches[i].src, block->start);         // Truncate match if it starts before block->start ...
          STAT   len = lz_matches[i].len - (src-lz_matches[i].src);
                 len = mymin (len, block->end - src);                   // ... or ends after block->end
          ENCODE_LZ_MATCH(stat, false, FUTURELZ_BASE_LEN,  src - block_pos, lz_matches[i].dest - lz_matches[i].src, len);
          block_pos = src;

          // Calculate decompression RAM.  Part II: add matches with source in the current block
          FUTURE_LZ_MATCH lz_match;
          lz_match.src  = src;
          lz_match.dest = src + (lz_matches[i].dest - lz_matches[i].src);
          lz_match.len  = len;
          if (lz_match.dest >= block->end  &&  lz_match.len < maximum_save)
          {
            ram += MEMORY_MANAGER::needmem(lz_match.len);
            lz_match_heap.insert(lz_match);
          }
        }
        i = saved_i;
        max_ram = mymax(ram,max_ram);

        // Write compressed block header to compressed file
        unsigned stat_size  =  (char*)stat - (char*)statbuf;
        if (FUTURE_LZ)
        {
          block->header[2] = stat_size;
          checked_file_write (fout, block->header, header_size);
        }

        // Write match list for compressed block to compressed file
        checked_file_write (fstat, statbuf, stat_size);
        *statsize_ptr++ = stat_size;
        total_stat_size += stat_size;

        if (FUTURE_LZ)
        {
          // Read next input block
          checked_file_read (ftemp, buf, block->size);

          // Copy literal data, not covered by LZ matches, to outbuf[]
          char *in = buf,  *out = outbuf;
          for (STAT *stat = block->statbuf;  stat < block->statend; )
          {
            DECODE_LZ_MATCH(stat, false, ROUND_MATCHES, BASE_LEN, 0,  lit_len, LZ_MATCH, lz_match);
            memcpy(out, in, lit_len);
            out += lit_len;
            in  += lit_len + lz_match.len;
          }
          memcpy(out, in, block->size - (in-buf));
          out += block->size - (in-buf);

          // Write compressed block literals to compressed file
          checked_file_write (fout, outbuf, out-outbuf);

          if (verbosity)
          {
            processed += block->size;
            double GlobalTime = GetGlobalTime()-GlobalTime0;
            if (processed==origsize || GlobalTime-LastGlobalTime>TimeInterval)
            {
              LastGlobalTime = GlobalTime;
              char remains[100], remains0[100], text[100], console_title[MY_FILENAME_MAX+100];

              int percents = int(double(processed)*100/origsize);
              int remain = int(round(double(origsize-processed)/processed * (GlobalTime - OperationStartGlobalTime)));
              if (remain>=3600)
                   sprintf (remains0, "%02d:%02d:%02d", remain / 3600, (remain % 3600) / 60, remain % 60);
              else sprintf (remains0, "%02d:%02d", remain / 60, remain % 60);

              sprintf (console_title, "%d%% %s | Second pass over %s", percents, remains0, (strequ (finame, "-")? "stdin" : finame));
              EnvSetConsoleTitleA (console_title);

              sprintf (text, "%.1lf%%   Remains %s   ", floor(double(processed)*1000/origsize)/10, remains0);
              fprintf (stderr, "%.*s%s", last_textlen, "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b", text);  last_textlen = strlen(text);
              Taskbar_SetProgressValue (processed, origsize);
            }
          }
        }
      }


      // 4. Write compressed file footer
      if (INDEX_LZ)
      {
        unsigned statsize_size  =  (BYTE*)statsize_ptr - (BYTE*)statsize_buf;
        header[0] = total_stat_size;
        header[1] = total_stat_size>>32;
        header[2] = INDEX_LZ_FOOTER_SIZE+statsize_size;   // footer size
        header[3] = SREP_FOOTER_VERSION1;                 // footer version
        header[4] = ~SREP_SIGNATURE;                      // footer signature
        header[5] = ~BULAT_ZIGANSHIN_SIGNATURE;
        checked_file_write (fout, statsize_buf, statsize_size);
        checked_file_write (fout, header, INDEX_LZ_FOOTER_SIZE);
      }
    }
    if (verbosity)
      print_info ((IO_LZ?"\n":"\r"), max_ram, maximum_save, total_stat_size, (IO_LZ? ROUND_MATCHES : false), compsize);
  }
  else
  {
    //*********************************************************************************************************
    /// DECOMPRESSION / INFORMATION
    //*********************************************************************************************************

    unsigned compbufsize = bufsize + sizeof(STAT)*(MAX_HEADER_SIZE+MAX_HASH_SIZE+FUTURELZ_MAX_STATS_PER_BLOCK(bufsize));
    char *buf     = new char[compbufsize];
    char *out     = new char[bufsize];
    STAT *statbuf = (STAT*)buf,  *statptr = (STAT*)buf;
    STAT *statsize_buf = NULL,  *statsize_ptr = NULL,  *statsize_end = NULL;

    int io_mem = vm_block+bufsize+compbufsize+8*mb;
    MEMORY_MANAGER mm (vm_mem>=io_mem+vm_block*4? vm_mem-io_mem : vm_block*4);
    VIRTUAL_MEMORY_MANAGER vm(vmfile_name, vm_block);
    LZ_MATCH_HEAP lz_matches;
    FUTURE_LZ_MATCH barrier;  barrier.dest = Offset(-1);  lz_matches.insert(barrier);

    // Check header of compressed file
    int len = file_read (fin, header, sizeof(STAT)*ARCHIVE_HEADER_SIZE);
    if (len != sizeof(STAT)*ARCHIVE_HEADER_SIZE
     || header[0] != BULAT_ZIGANSHIN_SIGNATURE
     || header[1] != SREP_SIGNATURE)            error (ERROR_COMPRESSION, "Not an SREP compressed file: %s", finame);
    int format_version  =  header[2] & 255;
    if (format_version < SREP_FORMAT_VERSION1
     || format_version > SREP_FORMAT_VERSION4)  error (ERROR_COMPRESSION, "Incompatible compressed data format: v%d (%s supports only v%d..v%d) in file %s", format_version, program_version, SREP_FORMAT_VERSION1, SREP_FORMAT_VERSION4, finame);

    // Get compression params from the header
    unsigned BASE_LEN = header[3];
    int hash_num       = (header[2] >>  8) & 255;
    int hash_seed_size = (header[2] >> 16) & 255;
    int hash_size      =((header[2] >> 24) + 16) & 255;
    if (selected_hash->hash_func != NULL)      // unless hash checking was disabled by -hash- option
    {
      selected_hash = hash_by_num(hash_num);
      if (selected_hash == NULL) {
        fprintf (stderr, "Block checksums can't be checked since they are using unknown hash #%d-%d\n", hash_num, hash_size*CHAR_BIT);
        selected_hash = hash_by_name("", errcode);
      } else if (selected_hash->hash_func == NULL) {
        fprintf (stderr, "Block checksums can't be checked since they aren't saved in the compressed data\n");
      } else if (hash_seed_size > selected_hash->hash_seed_size  ||  hash_size > selected_hash->hash_size) {
        char temp[100];
        fprintf (stderr, "Block checksums can't be checked since they are using unsupported hashsize %s-%s%d", selected_hash->hash_name, hash_seed_size?show3(hash_seed_size*CHAR_BIT,temp,"-"):"", hash_size*CHAR_BIT);
        selected_hash = hash_by_name("", errcode);
      }
    }

    // For keyed hashes like VMAC, we should read the key (seed) and create a hash using this key
    len = file_read (fin, header, hash_seed_size);
    if (len!=hash_seed_size)   error (ERROR_COMPRESSION, "Decompression problem: unexpected end of file %s or I/O error", finame);
    if (selected_hash->new_hash)
    {
      hash_obj = selected_hash->new_hash (header, hash_seed_size);
    }
    unsigned full_archive_header_size = sizeof(STAT)*ARCHIVE_HEADER_SIZE + hash_seed_size;
    compsize = full_archive_header_size;

    const int  header_size    =  sizeof(STAT)*BLOCK_HEADER_SIZE + hash_size;  // compressed block header size
    const bool ROUND_MATCHES  =  (format_version == SREP_FORMAT_VERSION1);
    const bool IO_LZ          =  (format_version <= SREP_FORMAT_VERSION2);
    const bool FUTURE_LZ      =  (format_version == SREP_FORMAT_VERSION3);
    const bool INDEX_LZ       =  (format_version == SREP_FORMAT_VERSION4);
    sprintf (temp1, (BASE_LEN? " -l%d" : ""), BASE_LEN);
    if (cmdmode==INFORMATION)
      fprintf (stderr, "%s:%s -hash=%s%s",  FUTURE_LZ? "Future-LZ":INDEX_LZ? "Index-LZ":"I/O LZ",  temp1,  selected_hash->hash_name,  INDEX_LZ? "":"\n");

    // INDEX_LZ: Read match list from footer of the compressed file
    if (INDEX_LZ)
    {
      file_seek (fin, filesize-INDEX_LZ_FOOTER_SIZE);
      checked_file_read (fin, header, INDEX_LZ_FOOTER_SIZE);

      unsigned footer_version = (header[3] & 255);
      unsigned footer_size = header[2];
      Offset stat_size = header[0] + (Offset(header[1])<<32),  stats_count = stat_size/sizeof(STAT),  lz_matches_count = stats_count/STATS_PER_MATCH(ROUND_MATCHES);
      compsize += footer_size+stat_size;

      if (header[5] != ~BULAT_ZIGANSHIN_SIGNATURE
       || header[4] != ~SREP_SIGNATURE)            error (ERROR_COMPRESSION, "Not found SREP compressed file footer in file %s", finame);
      if (footer_version != SREP_FOOTER_VERSION1)  error (ERROR_COMPRESSION, "Incompatible compressed file footer format: v%d (%s supports only v%d) in file %s", footer_version, program_version, SREP_FOOTER_VERSION1, finame);
      if (compsize > filesize)                     error (ERROR_COMPRESSION, "Broken SREP compressed file footer: %0.lf bytes footer + %0.lf bytes index in file %s", double(footer_size), double(stat_size), finame);

      // Read match list
      statbuf = statptr = new STAT[stats_count];
      file_seek (fin, filesize-footer_size-stat_size);
      checked_file_read (fin, statbuf, stat_size);

      // Read block list (count of matches for every block)
      unsigned total_blocks  =  (footer_size-INDEX_LZ_FOOTER_SIZE)/sizeof(STAT);
      statsize_buf = statsize_ptr = new STAT[total_blocks];
      statsize_end = statsize_buf+total_blocks;
      checked_file_read (fin, statsize_buf, total_blocks*sizeof(STAT));

      file_seek (fin, full_archive_header_size);

      if (cmdmode==INFORMATION)
      {
        // Original file size = literal bytes + match bytes
        origsize = filesize-footer_size-stat_size-full_archive_header_size-total_blocks*header_size;   // compute literal bytes

        // Read first block header in order to determine block size
        int len = file_read (fin, header, header_size);
        if (len!=header_size)   error (ERROR_COMPRESSION, "Decompression problem: unexpected end of file %s or I/O error", finame);
        unsigned block_size = header[1];

        // Calculate how much RAM will be required for decompression
        STAT *stat = statbuf;
        for (int i = 0; i < total_blocks; ++i)
        {
          Offset block_end = Offset(i+1)*block_size;
          for (LZ_MATCH_ITERATOR lz_match = lz_matches.begin();  lz_match->dest < block_end;  lz_match = lz_matches.begin())
          {
            ram -= MEMORY_MANAGER::needmem(lz_match->len);
            lz_matches.erase(lz_match);
          }

          Offset block_pos = Offset(i)*block_size;                                                     // current position in the decompressed file
          for (STAT *statend = stat+statsize_buf[i]/sizeof(STAT);  stat<statend;  )
          {
            DECODE_LZ_MATCH(stat, true, ROUND_MATCHES, BASE_LEN, block_pos,  lit_len, FUTURE_LZ_MATCH, lz_match);
            origsize += lz_match.len;                                                                  // add match bytes to the origsize
            block_pos = lz_match.src;
            if (lz_match.dest >= block_end  &&  lz_match.len < maximum_save)
            {
              ram += MEMORY_MANAGER::needmem(lz_match.len);
              lz_matches.insert(lz_match);
            }
          }
          max_ram = mymax(ram,max_ram);
        }

        char temp1[100], temp2[100], temp3[100];
        fprintf (stderr, ".  %s -> %s: %.2lf%%\n", show3(origsize,temp1), show3(filesize,temp2), double(filesize)*100/origsize);
        print_info ("", max_ram, maximum_save, stat_size, ROUND_MATCHES, filesize);

        goto cleanup;
      }
    }

    // If we will need to reread data from the stdout, it will be wise to duplicate them to tempfile
    if ((IO_LZ || maximum_save!=unsigned(-1))  &&  strequ(foutname,"-"))
    {
      if (!tempfile)
        tempfile = DEFAULT_TEMPFILE;
      else if (*tempfile==0)
        error (ERROR_IO, "Writing decompressed data to stdout without tempfile isn't supported for this file and settings");
    }

    ftemp  =  (tempfile && *tempfile)? fopen (tempfile, "w+b") : fout;
    if (ftemp == NULL)  error (ERROR_IO, "Can't open tempfile %s for write", tempfile);

    Offset statsize = 0;
    double OperationStartGlobalTime = (LastGlobalTime = GetGlobalTime() - GlobalTime0);

    // Decompress data by blocks until EOF
    for (bool finished=false; !finished; )
    {
      // Read block header
      int len = file_read (fin, header, header_size);
      // If there is no more data or EOF header (two zero 32-bit words) detected
      if ((len==0  ||  len>=2*sizeof(STAT) && header[0]==0 && header[1]==0)  &&  lz_matches.size()==1)   {finished=true; goto print_decompression_stats;}
      if (len!=header_size)   error (ERROR_COMPRESSION, "Decompression problem: unexpected end of file %s or I/O error", finame);

     {unsigned datasize1 = header[0],
               origsize1 = header[1],
               statsize1 = header[2],
               compsize1 = datasize1 + statsize1;
      if (origsize1>bufsize)                                                         error (ERROR_COMPRESSION, "Decompression problem: uncompressed block size is %u bytes, while maximum supported size is %u bytes", origsize1, bufsize);
      if (compsize1>compbufsize || header[0]>compbufsize || header[2]>compbufsize)   error (ERROR_COMPRESSION, "Decompression problem: compressed block size is %u bytes, while maximum supported size is %u bytes",   compsize1, compbufsize);

      // Update statistics
      Offset block_start = origsize;        // first byte in the block
      statsize += statsize1;
      compsize += header_size + compsize1;
      origsize += origsize1;
      Offset block_end = origsize;          // last byte in the block

      // Read compressed data, part I: the match list
      len = file_read (fstat, buf, statsize1);
      if (len!=statsize1)   error (ERROR_COMPRESSION, "Decompression problem: unexpected end of file %s or I/O error", *index_file? index_file : finame);

      STAT *statendptr = (STAT*)(buf+statsize1);                // Should point AFTER the last match belonging to the block
      if (INDEX_LZ) {
        statendptr = statptr + (*statsize_ptr++)/sizeof(STAT);
        finished = (statsize_ptr==statsize_end);
      }


      if (cmdmode==INFORMATION)
      {
        // Skip literal data since we only need to compute uncompressed file size and decompression RAM
        file_seek_cur (fin, datasize1);
        if (IO_LZ)
          goto print_decompression_stats;

        // Calculate how much RAM will be required for decompression.  Part I: remove matches with destination in the current block
        for (LZ_MATCH_ITERATOR lz_match = lz_matches.begin();  lz_match->dest < block_end;  lz_match = lz_matches.begin())
        {
          ram -= MEMORY_MANAGER::needmem(lz_match->len);
          lz_matches.erase(lz_match);
        }

        // Calculate decompression RAM.  Part II: add matches with source in the current block
        Offset block_pos = block_start;  // current position in the decompressed file
        for (STAT *stat = statptr;  stat<statendptr;  )
        {
          DECODE_LZ_MATCH(stat, true, ROUND_MATCHES, BASE_LEN, block_pos,  lit_len, FUTURE_LZ_MATCH, lz_match);
          block_pos = lz_match.src;
          if (lz_match.dest >= block_end  &&  lz_match.len < maximum_save)
          {
            ram += MEMORY_MANAGER::needmem(lz_match.len);
            lz_matches.insert(lz_match);
          }
        }
        max_ram = mymax(ram,max_ram);

        goto print_decompression_stats;
      }


      // Read compressed data, part II: literals
      len = file_read (fin, buf+statsize1, datasize1);
      if (len!=datasize1)   error (ERROR_COMPRESSION, "Decompression problem: unexpected end of file %s or I/O error", finame);

      // Perform decompression
      bool ok = IO_LZ? decompress           (ROUND_MATCHES, BASE_LEN, ftemp, block_start, statptr,             buf+statsize1, buf+compsize1, out, out+origsize1)
                     : decompress_FUTURE_LZ (ROUND_MATCHES, BASE_LEN, ftemp, block_start, statptr, statendptr, buf+statsize1, buf+compsize1, out, out+origsize1, mm, vm, lz_matches, maximum_save);
      if (!ok)   error (ERROR_COMPRESSION, "Decompression problem: broken compressed data");

      if (INDEX_LZ)
        statptr = statendptr;

      // Check hashsum of decompressed data
      if (selected_hash->hash_func) {
        char checksum [MAX_HASH_SIZE];
        selected_hash->hash_func (hash_obj, out,origsize1, checksum);
        if (memcmp (checksum, header+3, hash_size) != EQUAL)   error (ERROR_COMPRESSION, "Decompression problem: checksum of decompressed data is not the same as checksum of original data");
      }

      // Write decompressed data to output file, plus to temporary file if it's different
      file_seek (ftemp, block_start);
      checked_file_write (ftemp, out, origsize1);
      if (tempfile && *tempfile)
        checked_file_write (fout, out, origsize1);}

print_decompression_stats:
      if (verbosity)
      {
        double GlobalTime = GetGlobalTime()-GlobalTime0;
        if (origsize!=last_origsize  &&  (finished || GlobalTime-LastGlobalTime>TimeInterval))
        {
          LastGlobalTime = GlobalTime;  last_origsize = origsize;  double CPUTime = GetCPUTime();
          char stats[1000], total_reads_str[100], vm_stats_str[100], temp1[100], temp2[100];
          char remains[100], remains0[100], console_title[MY_FILENAME_MAX+100];

          int percents = int(double(compsize)*100/filesize);
          int remain = int(round(double(filesize-compsize)/compsize * (GlobalTime - OperationStartGlobalTime)));
          if (remain>=3600)
               sprintf (remains0, "%02d:%02d:%02d", remain / 3600, (remain % 3600) / 60, remain % 60);
          else sprintf (remains0, "%02d:%02d", remain / 60, remain % 60);
          sprintf (remains, ".  Remains %s   ", remains0);

          sprintf (total_reads_str, maximum_save != unsigned(-1)? ", I/Os %.0lf":"", double(total_reads));
          sprintf (vm_stats_str, vm.total_write? ", VM %d/%d, R/W %d/%d":"", int(vm.current_mem()/mb), int(vm.max_mem()/mb), int(vm.total_read/mb), int(vm.total_write/mb));
          sprintf (stats, (IO_LZ || !print_pc? "" : ".  Matches %.0lf %.0lf %.0lf%s, RAM %d/%d%s"),
                   double(cur_matches), double(max_matches), double(total_matches), total_reads_str,
                   int(mm.current_mem()/mb), int(mm.max_mem()/mb), vm_stats_str);

          fprintf (stderr, "\r%d%%: %s -> %s: %.2lf%%.  Cpu %.0lf mb/s (%.3lf sec), real %.0lf mb/s (%.3lf sec) = %.0lf%%%s%s",
                   percents, show3(compsize,temp1), show3(origsize,temp2), double(compsize)*100/origsize,
                   origsize/CPUTime/mb, CPUTime, origsize/GlobalTime/mb, GlobalTime, CPUTime/GlobalTime*100, (*stats? stats:remains), newline);

          sprintf (console_title, "%d%% %s | Extracting %s", percents, remains0, (strequ (finame, "-")? "from stdin" : finame));
          EnvSetConsoleTitleA (console_title);

          Taskbar_SetProgressValue (compsize, filesize);
        }
      }
    }
    if (cmdmode==INFORMATION)
      print_info ("\n", max_ram, maximum_save, statsize, ROUND_MATCHES, filesize);
  }


  //*********************************************************************************************************
  /// CLOSE FILES
  //*********************************************************************************************************

cleanup:
  clear_window_title();
  fprintf (stderr, "\n");
  fclose(fin);
  fclose(fout);
  if (fstat!=fin && fstat!=fout)
    fclose(fstat);
  if (tempfile && *tempfile)
    fclose(ftemp),
    remove(tempfile);
  if (errcode)
  {
    // Delete output files on error
    if (!strequ(foutname,"-"))
      remove(foutname);
    if (index_file)
      remove(index_file);
    return errcode;
  }
  if (warnings==0 && delete_input_files && !strequ(finame,"-"))
    remove(finame);
  return warnings? WARNINGS : NO_ERRORS;
}

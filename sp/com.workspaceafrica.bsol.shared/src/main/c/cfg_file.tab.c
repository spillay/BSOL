/* A Bison parser, made by GNU Bison 3.0.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2013 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.0.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* Copy the first part of user declarations.  */
#line 1 "cfg_file.y" /* yacc.c:339  */

/*  
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2008  Maxim Krasnyansky <max_mk@yahoo.com>

    VTun has been derived from VPPP package by Maxim Krasnyansky. 

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 */

/*
 * $Id: cfg_file.y,v 1.8.2.6 2012/07/09 01:01:08 mtbishop Exp $
 */ 

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <syslog.h>

#include "compat.h"
#include "vtun.h"
#include "lib.h"

int lineno = 1;

struct vtun_host *parse_host;
extern struct vtun_host default_host;

llist  *parse_cmds;
struct vtun_cmd parse_cmd;

llist host_list;

int  cfg_error(const char *fmt, ...);
int  add_cmd(llist *cmds, char *prog, char *args, int flags);
void *cp_cmd(void *d, void *u);
int  free_cmd(void *d, void *u);

void copy_addr(struct vtun_host *to, struct vtun_host *from);
int  free_host(void *d, void *u);
void free_addr(struct vtun_host *h);
void free_host_list(void);

int  parse_syslog(char *facility);

int yyparse(void);
int yylex(void);	
int yyerror(char *s); 

#define YYERROR_VERBOSE 1


#line 132 "cfg_file.tab.c" /* yacc.c:339  */

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "cfg_file.tab.h".  */
#ifndef YY_YY_CFG_FILE_TAB_H_INCLUDED
# define YY_YY_CFG_FILE_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    K_OPTIONS = 258,
    K_DEFAULT = 259,
    K_PORT = 260,
    K_BINDADDR = 261,
    K_PERSIST = 262,
    K_TIMEOUT = 263,
    K_PASSWD = 264,
    K_PROG = 265,
    K_PPP = 266,
    K_SPEED = 267,
    K_IFCFG = 268,
    K_FWALL = 269,
    K_ROUTE = 270,
    K_DEVICE = 271,
    K_MULTI = 272,
    K_SRCADDR = 273,
    K_IFACE = 274,
    K_ADDR = 275,
    K_TYPE = 276,
    K_PROT = 277,
    K_NAT_HACK = 278,
    K_COMPRESS = 279,
    K_ENCRYPT = 280,
    K_KALIVE = 281,
    K_STAT = 282,
    K_UP = 283,
    K_DOWN = 284,
    K_SYSLOG = 285,
    K_IPROUTE = 286,
    K_HOST = 287,
    K_ERROR = 288,
    WORD = 289,
    PATH = 290,
    STRING = 291,
    NUM = 292,
    DNUM = 293
  };
#endif
/* Tokens.  */
#define K_OPTIONS 258
#define K_DEFAULT 259
#define K_PORT 260
#define K_BINDADDR 261
#define K_PERSIST 262
#define K_TIMEOUT 263
#define K_PASSWD 264
#define K_PROG 265
#define K_PPP 266
#define K_SPEED 267
#define K_IFCFG 268
#define K_FWALL 269
#define K_ROUTE 270
#define K_DEVICE 271
#define K_MULTI 272
#define K_SRCADDR 273
#define K_IFACE 274
#define K_ADDR 275
#define K_TYPE 276
#define K_PROT 277
#define K_NAT_HACK 278
#define K_COMPRESS 279
#define K_ENCRYPT 280
#define K_KALIVE 281
#define K_STAT 282
#define K_UP 283
#define K_DOWN 284
#define K_SYSLOG 285
#define K_IPROUTE 286
#define K_HOST 287
#define K_ERROR 288
#define WORD 289
#define PATH 290
#define STRING 291
#define NUM 292
#define DNUM 293

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE YYSTYPE;
union YYSTYPE
{
#line 67 "cfg_file.y" /* yacc.c:355  */

   char *str;
   int  num;
   struct { int num1; int num2; } dnum;

#line 254 "cfg_file.tab.c" /* yacc.c:355  */
};
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);

#endif /* !YY_YY_CFG_FILE_TAB_H_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 269 "cfg_file.tab.c" /* yacc.c:358  */

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif


#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   217

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  42
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  24
/* YYNRULES -- Number of rules.  */
#define YYNRULES  88
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  142

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   293

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      39,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    40,     2,    41,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,    86,    86,    87,    90,    91,    93,    93,    98,    98,
     131,   138,   139,   143,   144,   149,   151,   156,   161,   166,
     171,   176,   181,   186,   191,   193,   200,   205,   210,   215,
     222,   226,   233,   240,   241,   246,   247,   252,   257,   261,
     265,   273,   282,   282,   287,   295,   295,   300,   307,   314,
     319,   324,   333,   335,   335,   340,   340,   345,   352,   359,
     364,   371,   376,   384,   390,   391,   392,   396,   402,   408,
     414,   418,   424,   425,   426,   429,   430,   430,   438,   443,
     448,   453,   458,   463,   470,   471,   475,   479,   483
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "K_OPTIONS", "K_DEFAULT", "K_PORT",
  "K_BINDADDR", "K_PERSIST", "K_TIMEOUT", "K_PASSWD", "K_PROG", "K_PPP",
  "K_SPEED", "K_IFCFG", "K_FWALL", "K_ROUTE", "K_DEVICE", "K_MULTI",
  "K_SRCADDR", "K_IFACE", "K_ADDR", "K_TYPE", "K_PROT", "K_NAT_HACK",
  "K_COMPRESS", "K_ENCRYPT", "K_KALIVE", "K_STAT", "K_UP", "K_DOWN",
  "K_SYSLOG", "K_IPROUTE", "K_HOST", "K_ERROR", "WORD", "PATH", "STRING",
  "NUM", "DNUM", "'\\n'", "'{'", "'}'", "$accept", "config", "statement",
  "$@1", "$@2", "options", "option", "bindaddr_option", "syslog_opt",
  "host_options", "host_option", "$@3", "$@4", "$@5", "$@6", "compress",
  "keepalive", "srcaddr_options", "srcaddr_option", "command_options",
  "command_option", "$@7", "prog_options", "prog_option", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,    10,
     123,   125
};
# endif

#define YYPACT_NINF -75

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-75)))

#define YYTABLE_NINF -1

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -75,     0,   -75,   -29,   -75,   -75,   -75,   -75,   -75,    96,
     -26,   -19,   -11,    13,    -8,   -27,    38,    62,    63,    69,
      66,   -32,    64,   -75,   -75,     4,   -75,   116,   116,   -75,
     -13,   -75,   -75,   -75,   -75,   -75,   -75,   -75,   -75,   -75,
     -75,   -75,   -75,   -75,   -75,    75,    76,    80,    49,    82,
      81,    79,    83,    84,    85,   -75,    93,   -75,    94,   -75,
     -75,   -75,   -75,    39,   -75,    67,   -12,   102,   -75,   105,
     -75,   -75,   -75,   -75,   -75,   -75,   -75,    11,   -75,   -75,
     -75,    21,   -75,    44,   -75,   113,   114,   -75,   -75,   -75,
     -75,   -75,   -75,   -75,   121,     2,   128,   -75,     8,   -75,
     -75,   -75,   -75,   -75,   -75,   -75,   -75,   -75,   178,   178,
     -75,   -75,   -75,   -75,   -75,   -75,   -75,   127,   129,   130,
     131,   133,   -75,   -75,   137,   -75,   146,    34,   -75,   -75,
     -75,   -75,   -75,   -75,   -75,   -75,   -75,   -75,   -75,    34,
     -75,   -75
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     1,     0,     6,     8,    10,     4,     3,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    25,    13,     0,    11,     0,     0,    14,
       0,    18,    19,    20,    22,    21,    16,    17,    32,    31,
      30,    24,    23,     5,    12,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    42,     0,    45,     0,    53,
      55,    57,    35,     0,    33,     0,     0,     0,    29,     0,
      48,    39,    36,    40,    41,    37,    38,    64,    49,    50,
      51,     0,    44,     0,    47,     0,     0,     7,    34,     9,
      27,    28,    26,    15,     0,     0,     0,    71,     0,    65,
      60,    58,    59,    43,    63,    61,    62,    46,    72,    72,
      70,    68,    69,    67,    52,    66,    76,     0,     0,     0,
       0,     0,    83,    75,     0,    73,     0,     0,    78,    79,
      81,    80,    82,    54,    74,    56,    86,    87,    88,    77,
      84,    85
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -75,   -75,   -75,   -75,   -75,   -75,   139,   -75,   -75,   143,
     -23,   -75,   -75,   -75,   -75,   -75,   -75,   -75,    74,    65,
     -74,   -75,   -75,    36
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     8,    10,    11,    25,    26,    69,    41,    63,
      64,    81,    83,    85,    86,   103,   107,    98,    99,   124,
     125,   127,   139,   140
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_uint8 yytable[] =
{
       2,    38,    39,     3,     4,    40,    66,    67,    32,    12,
      13,     9,    14,    94,    27,    15,    94,    16,    17,    18,
      68,    28,    90,    19,    91,    20,    29,    95,    96,    31,
      95,    96,     5,     6,    21,    22,   111,    23,   112,     7,
      88,    97,    88,    24,    97,    43,    45,    46,    47,   114,
     134,    48,   134,    30,   100,    49,    50,    51,   101,   102,
      52,    53,    54,    55,    56,    57,    58,    59,    60,   136,
     137,   138,    61,    33,    45,    46,    47,   104,    62,    48,
      87,   105,   106,    49,    50,    51,    73,    74,    52,    53,
      54,    55,    56,    57,    58,    59,    60,    34,    35,    42,
      61,    12,    13,    37,    14,    36,    62,    15,    89,    16,
      17,    18,    70,    71,    72,    19,    75,    20,    76,    77,
      78,    79,    80,    45,    46,    47,    21,    22,    48,    23,
      82,    84,    49,    50,    51,    24,    92,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    93,   116,   117,    61,
     118,   119,   120,   108,   109,    62,   116,   117,   110,   118,
     119,   120,   113,   128,    44,   129,   130,   131,   121,   132,
     122,    65,   115,     0,   126,   141,   123,   121,   133,   122,
       0,     0,     0,     0,     0,   123,     0,   135,   116,   117,
       0,   118,   119,   120,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   121,
       0,   122,     0,     0,     0,     0,     0,   123
};

static const yytype_int16 yycheck[] =
{
       0,    33,    34,     3,     4,    37,    19,    20,    35,     5,
       6,    40,     8,     5,    40,    11,     5,    13,    14,    15,
      33,    40,    34,    19,    36,    21,    37,    19,    20,    37,
      19,    20,    32,    33,    30,    31,    34,    33,    36,    39,
      63,    33,    65,    39,    33,    41,     7,     8,     9,    41,
     124,    12,   126,    40,    33,    16,    17,    18,    37,    38,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    35,
      36,    37,    33,    35,     7,     8,     9,    33,    39,    12,
      41,    37,    38,    16,    17,    18,    37,    38,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    35,    35,    35,
      33,     5,     6,    37,     8,    36,    39,    11,    41,    13,
      14,    15,    37,    37,    34,    19,    34,    21,    37,    40,
      37,    37,    37,     7,     8,     9,    30,    31,    12,    33,
      37,    37,    16,    17,    18,    39,    34,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    41,    10,    11,    33,
      13,    14,    15,    40,    40,    39,    10,    11,    37,    13,
      14,    15,    34,    36,    25,    36,    36,    36,    31,    36,
      33,    28,    98,    -1,   109,   139,    39,    31,    41,    33,
      -1,    -1,    -1,    -1,    -1,    39,    -1,    41,    10,    11,
      -1,    13,    14,    15,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    31,
      -1,    33,    -1,    -1,    -1,    -1,    -1,    39
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    43,     0,     3,     4,    32,    33,    39,    44,    40,
      45,    46,     5,     6,     8,    11,    13,    14,    15,    19,
      21,    30,    31,    33,    39,    47,    48,    40,    40,    37,
      40,    37,    35,    35,    35,    35,    36,    37,    33,    34,
      37,    50,    35,    41,    48,     7,     8,     9,    12,    16,
      17,    18,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    33,    39,    51,    52,    51,    19,    20,    33,    49,
      37,    37,    34,    37,    38,    34,    37,    40,    37,    37,
      37,    53,    37,    54,    37,    55,    56,    41,    52,    41,
      34,    36,    34,    41,     5,    19,    20,    33,    59,    60,
      33,    37,    38,    57,    33,    37,    38,    58,    40,    40,
      37,    34,    36,    34,    41,    60,    10,    11,    13,    14,
      15,    31,    33,    39,    61,    62,    61,    63,    36,    36,
      36,    36,    36,    41,    62,    41,    35,    36,    37,    64,
      65,    65
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    42,    43,    43,    44,    44,    45,    44,    46,    44,
      44,    47,    47,    48,    48,    48,    48,    48,    48,    48,
      48,    48,    48,    48,    48,    48,    49,    49,    49,    49,
      50,    50,    50,    51,    51,    52,    52,    52,    52,    52,
      52,    52,    53,    52,    52,    54,    52,    52,    52,    52,
      52,    52,    52,    55,    52,    56,    52,    52,    57,    57,
      57,    58,    58,    58,    59,    59,    59,    60,    60,    60,
      60,    60,    61,    61,    61,    62,    63,    62,    62,    62,
      62,    62,    62,    62,    64,    64,    65,    65,    65
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     1,     4,     0,     5,     0,     5,
       1,     1,     2,     1,     2,     4,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     1,     2,     2,     2,     1,
       1,     1,     1,     1,     2,     1,     2,     2,     2,     2,
       2,     2,     0,     3,     2,     0,     3,     2,     2,     2,
       2,     2,     4,     0,     5,     0,     5,     1,     1,     1,
       1,     1,     1,     1,     0,     1,     2,     2,     2,     2,
       2,     1,     0,     1,     2,     1,     0,     3,     2,     2,
       2,     2,     2,     1,     1,     2,     1,     1,     1
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;                                                  \
    }                                                           \
while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, int yyrule)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
                                              );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            /* Fall through.  */
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
{
  YYUSE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;


/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yystacksize);

        yyss = yyss1;
        yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
                  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 6:
#line 93 "cfg_file.y" /* yacc.c:1646  */
    { 
		  parse_host = &default_host; 
                }
#line 1465 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 8:
#line 98 "cfg_file.y" /* yacc.c:1646  */
    { 
		  if( !(parse_host = malloc(sizeof(struct vtun_host))) ){
		     yyerror("No memory for the host");
		     YYABORT;
		  }

		  /* Fill new host struct with default values.
		   * MUST dup strings to be able to reread config.
		   */
	  	  memcpy(parse_host, &default_host, sizeof(struct vtun_host));
		  parse_host->host = strdup((yyvsp[0].str));
		  parse_host->passwd = NULL;

		  /* Copy local address */
		  copy_addr(parse_host, &default_host);

		  llist_copy(&default_host.up,&parse_host->up,cp_cmd,NULL);
		  llist_copy(&default_host.down,&parse_host->down,cp_cmd,NULL);

		}
#line 1490 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 9:
#line 119 "cfg_file.y" /* yacc.c:1646  */
    {
		  /* Check if session definition is complete */ 
		  if (!parse_host->passwd) {
		  	cfg_error("Ignored incomplete session definition '%s'", parse_host->host);
			free_host(parse_host, NULL);			
			free(parse_host);
		  } else {
		  	/* Add host to the list */
		  	llist_add(&host_list, (void *)parse_host);
		  }
		}
#line 1506 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 10:
#line 131 "cfg_file.y" /* yacc.c:1646  */
    {
		  cfg_error("Invalid clause '%s'",(yyvsp[0].str));
		  YYABORT;
		}
#line 1515 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 14:
#line 144 "cfg_file.y" /* yacc.c:1646  */
    { 
			  if(vtun.bind_addr.port == -1)
			     vtun.bind_addr.port = (yyvsp[0].num);
			}
#line 1524 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 16:
#line 151 "cfg_file.y" /* yacc.c:1646  */
    { 
			  if(vtun.svr_addr == NULL)
			    vtun.svr_addr = strdup((yyvsp[0].str));
			}
#line 1533 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 17:
#line 156 "cfg_file.y" /* yacc.c:1646  */
    { 
			  if(vtun.svr_type == -1)
			     vtun.svr_type = (yyvsp[0].num);
			}
#line 1542 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 18:
#line 161 "cfg_file.y" /* yacc.c:1646  */
    {  
			  if(vtun.timeout == -1)
			     vtun.timeout = (yyvsp[0].num); 	
			}
#line 1551 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 19:
#line 166 "cfg_file.y" /* yacc.c:1646  */
    {
			  free(vtun.ppp);
			  vtun.ppp = strdup((yyvsp[0].str));
			}
#line 1560 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 20:
#line 171 "cfg_file.y" /* yacc.c:1646  */
    {
			  free(vtun.ifcfg);
			  vtun.ifcfg = strdup((yyvsp[0].str));
			}
#line 1569 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 21:
#line 176 "cfg_file.y" /* yacc.c:1646  */
    {   
			  free(vtun.route);  
			  vtun.route = strdup((yyvsp[0].str)); 	
			}
#line 1578 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 22:
#line 181 "cfg_file.y" /* yacc.c:1646  */
    {   
			  free(vtun.fwall);  
			  vtun.fwall = strdup((yyvsp[0].str)); 	
			}
#line 1587 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 23:
#line 186 "cfg_file.y" /* yacc.c:1646  */
    {   
			  free(vtun.iproute);  
			  vtun.iproute = strdup((yyvsp[0].str)); 	
			}
#line 1596 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 25:
#line 193 "cfg_file.y" /* yacc.c:1646  */
    {
			  cfg_error("Unknown option '%s'",(yyvsp[0].str));
			  YYABORT;
			}
#line 1605 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 26:
#line 200 "cfg_file.y" /* yacc.c:1646  */
    {
			  vtun.bind_addr.name = strdup((yyvsp[0].str));
			  vtun.bind_addr.type = VTUN_ADDR_NAME;
			}
#line 1614 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 27:
#line 205 "cfg_file.y" /* yacc.c:1646  */
    {
			  vtun.bind_addr.name = strdup((yyvsp[0].str));
			  vtun.bind_addr.type = VTUN_ADDR_IFACE;
			}
#line 1623 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 28:
#line 210 "cfg_file.y" /* yacc.c:1646  */
    {
			  vtun.bind_addr.name = strdup((yyvsp[0].str));
			  vtun.bind_addr.type = VTUN_ADDR_IFACE;
			}
#line 1632 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 29:
#line 215 "cfg_file.y" /* yacc.c:1646  */
    {
			  cfg_error("Unknown option '%s'",(yyvsp[0].str));
			  YYABORT;
			}
#line 1641 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 30:
#line 222 "cfg_file.y" /* yacc.c:1646  */
    {
                          vtun.syslog = (yyvsp[0].num);
  			}
#line 1649 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 31:
#line 226 "cfg_file.y" /* yacc.c:1646  */
    {
                          if (parse_syslog((yyvsp[0].str))) {
                            cfg_error("Unknown syslog facility '%s'", (yyvsp[0].str));
                            YYABORT;
                          }
                        }
#line 1660 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 32:
#line 233 "cfg_file.y" /* yacc.c:1646  */
    {
   			  cfg_error("Unknown syslog option '%s'",(yyvsp[0].str));
  			  YYABORT;
			}
#line 1669 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 36:
#line 247 "cfg_file.y" /* yacc.c:1646  */
    {
			  free(parse_host->passwd);
			  parse_host->passwd = strdup((yyvsp[0].str));
			}
#line 1678 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 37:
#line 252 "cfg_file.y" /* yacc.c:1646  */
    {
			  free(parse_host->dev);
			  parse_host->dev = strdup((yyvsp[0].str));
			}
#line 1687 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 38:
#line 257 "cfg_file.y" /* yacc.c:1646  */
    { 
			  parse_host->multi = (yyvsp[0].num);
			}
#line 1695 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 39:
#line 261 "cfg_file.y" /* yacc.c:1646  */
    { 
			  parse_host->timeout = (yyvsp[0].num);
			}
#line 1703 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 40:
#line 265 "cfg_file.y" /* yacc.c:1646  */
    { 
			  if( (yyvsp[0].num) ){ 
			     parse_host->spd_in = parse_host->spd_out = (yyvsp[0].num);
			     parse_host->flags |= VTUN_SHAPE;
			  } else 
			     parse_host->flags &= ~VTUN_SHAPE;
			}
#line 1715 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 41:
#line 273 "cfg_file.y" /* yacc.c:1646  */
    { 
			  if( yylval.dnum.num1 || yylval.dnum.num2 ){ 
			     parse_host->spd_out = yylval.dnum.num1;
		             parse_host->spd_in = yylval.dnum.num2; 	
			     parse_host->flags |= VTUN_SHAPE;
			  } else 
			     parse_host->flags &= ~VTUN_SHAPE;
			}
#line 1728 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 42:
#line 282 "cfg_file.y" /* yacc.c:1646  */
    {
			  parse_host->flags &= ~(VTUN_ZLIB | VTUN_LZO); 
			}
#line 1736 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 44:
#line 287 "cfg_file.y" /* yacc.c:1646  */
    {  
			  if( (yyvsp[0].num) ){
			     parse_host->flags |= VTUN_ENCRYPT;
			     parse_host->cipher = (yyvsp[0].num);
			  } else
			     parse_host->flags &= ~VTUN_ENCRYPT;
			}
#line 1748 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 45:
#line 295 "cfg_file.y" /* yacc.c:1646  */
    {
			  parse_host->flags &= ~VTUN_KEEP_ALIVE; 
			}
#line 1756 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 47:
#line 300 "cfg_file.y" /* yacc.c:1646  */
    {
			  if( (yyvsp[0].num) )
			     parse_host->flags |= VTUN_STAT;
			  else
			     parse_host->flags &= ~VTUN_STAT;
			}
#line 1767 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 48:
#line 307 "cfg_file.y" /* yacc.c:1646  */
    { 
	      		  parse_host->persist = (yyvsp[0].num);

			  if(vtun.persist == -1) 
			     vtun.persist = (yyvsp[0].num); 	
			}
#line 1778 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 49:
#line 314 "cfg_file.y" /* yacc.c:1646  */
    {  
			  parse_host->flags &= ~VTUN_TYPE_MASK;
			  parse_host->flags |= (yyvsp[0].num);
			}
#line 1787 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 50:
#line 319 "cfg_file.y" /* yacc.c:1646  */
    {  
			  parse_host->flags &= ~VTUN_PROT_MASK;
			  parse_host->flags |= (yyvsp[0].num);
			}
#line 1796 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 51:
#line 324 "cfg_file.y" /* yacc.c:1646  */
    {  
#ifdef ENABLE_NAT_HACK
			  parse_host->flags &= ~VTUN_NAT_HACK_MASK;
			  parse_host->flags |= (yyvsp[0].num);
#else
			  cfg_error("This vtund binary was built with the NAT hack disabled for security purposes.");
#endif
			}
#line 1809 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 53:
#line 335 "cfg_file.y" /* yacc.c:1646  */
    { 
			  parse_cmds = &parse_host->up; 
   			  llist_free(parse_cmds, free_cmd, NULL);   
			}
#line 1818 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 55:
#line 340 "cfg_file.y" /* yacc.c:1646  */
    { 
			  parse_cmds = &parse_host->down; 
   			  llist_free(parse_cmds, free_cmd, NULL);   
			}
#line 1827 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 57:
#line 345 "cfg_file.y" /* yacc.c:1646  */
    {
			  cfg_error("Unknown option '%s'",(yyvsp[0].str));
			  YYABORT;
			}
#line 1836 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 58:
#line 352 "cfg_file.y" /* yacc.c:1646  */
    { 
			  if( (yyvsp[0].num) ){  
      			     parse_host->flags |= VTUN_ZLIB; 
			     parse_host->zlevel = (yyvsp[0].num);
			  }
			}
#line 1847 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 59:
#line 359 "cfg_file.y" /* yacc.c:1646  */
    {
			  parse_host->flags |= yylval.dnum.num1;
		          parse_host->zlevel = yylval.dnum.num2;
  			}
#line 1856 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 60:
#line 364 "cfg_file.y" /* yacc.c:1646  */
    {
			  cfg_error("Unknown compression '%s'",(yyvsp[0].str));
			  YYABORT;
			}
#line 1865 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 61:
#line 371 "cfg_file.y" /* yacc.c:1646  */
    { 
			  if( (yyvsp[0].num) )
			     parse_host->flags |= VTUN_KEEP_ALIVE;
			}
#line 1874 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 62:
#line 376 "cfg_file.y" /* yacc.c:1646  */
    {
			  if( yylval.dnum.num1 ){
			     parse_host->flags |= VTUN_KEEP_ALIVE;
			     parse_host->ka_interval = yylval.dnum.num1;
		             parse_host->ka_maxfail  = yylval.dnum.num2;
			  }
  			}
#line 1886 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 63:
#line 384 "cfg_file.y" /* yacc.c:1646  */
    {
			  cfg_error("Unknown keepalive option '%s'",(yyvsp[0].str));
			  YYABORT;
			}
#line 1895 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 67:
#line 396 "cfg_file.y" /* yacc.c:1646  */
    {
			  free_addr(parse_host);
			  parse_host->src_addr.name = strdup((yyvsp[0].str));
			  parse_host->src_addr.type = VTUN_ADDR_NAME;
			}
#line 1905 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 68:
#line 402 "cfg_file.y" /* yacc.c:1646  */
    {
			  free_addr(parse_host);
			  parse_host->src_addr.name = strdup((yyvsp[0].str));
			  parse_host->src_addr.type = VTUN_ADDR_IFACE;
			}
#line 1915 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 69:
#line 408 "cfg_file.y" /* yacc.c:1646  */
    {
			  free_addr(parse_host);
			  parse_host->src_addr.name = strdup((yyvsp[0].str));
			  parse_host->src_addr.type = VTUN_ADDR_IFACE;
			}
#line 1925 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 70:
#line 414 "cfg_file.y" /* yacc.c:1646  */
    {
			  parse_host->src_addr.port = (yyvsp[0].num);
			}
#line 1933 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 71:
#line 418 "cfg_file.y" /* yacc.c:1646  */
    {
			  cfg_error("Unknown option '%s'",(yyvsp[0].str));
			  YYABORT;
			}
#line 1942 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 76:
#line 430 "cfg_file.y" /* yacc.c:1646  */
    {
			  memset(&parse_cmd, 0, sizeof(struct vtun_cmd));
			}
#line 1950 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 77:
#line 433 "cfg_file.y" /* yacc.c:1646  */
    {
			  add_cmd(parse_cmds, parse_cmd.prog, 
				  parse_cmd.args, parse_cmd.flags);
			}
#line 1959 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 78:
#line 438 "cfg_file.y" /* yacc.c:1646  */
    {   
			  add_cmd(parse_cmds, strdup(vtun.ppp), strdup((yyvsp[0].str)), 
					VTUN_CMD_DELAY);
			}
#line 1968 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 79:
#line 443 "cfg_file.y" /* yacc.c:1646  */
    {   
			  add_cmd(parse_cmds, strdup(vtun.ifcfg),strdup((yyvsp[0].str)),
					VTUN_CMD_WAIT);
			}
#line 1977 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 80:
#line 448 "cfg_file.y" /* yacc.c:1646  */
    {   
			  add_cmd(parse_cmds, strdup(vtun.route),strdup((yyvsp[0].str)),
					VTUN_CMD_WAIT);
			}
#line 1986 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 81:
#line 453 "cfg_file.y" /* yacc.c:1646  */
    {   
			  add_cmd(parse_cmds, strdup(vtun.fwall),strdup((yyvsp[0].str)),
					VTUN_CMD_WAIT);
			}
#line 1995 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 82:
#line 458 "cfg_file.y" /* yacc.c:1646  */
    {   
			  add_cmd(parse_cmds, strdup(vtun.iproute),strdup((yyvsp[0].str)),
					VTUN_CMD_WAIT);
			}
#line 2004 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 83:
#line 463 "cfg_file.y" /* yacc.c:1646  */
    {
			  cfg_error("Unknown cmd '%s'",(yyvsp[0].str));
			  YYABORT;
			}
#line 2013 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 86:
#line 475 "cfg_file.y" /* yacc.c:1646  */
    {
			  parse_cmd.prog = strdup((yyvsp[0].str));
			}
#line 2021 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 87:
#line 479 "cfg_file.y" /* yacc.c:1646  */
    {
			  parse_cmd.args = strdup((yyvsp[0].str));
			}
#line 2029 "cfg_file.tab.c" /* yacc.c:1646  */
    break;

  case 88:
#line 483 "cfg_file.y" /* yacc.c:1646  */
    {
			  parse_cmd.flags = (yyvsp[0].num);
			}
#line 2037 "cfg_file.tab.c" /* yacc.c:1646  */
    break;


#line 2041 "cfg_file.tab.c" /* yacc.c:1646  */
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 487 "cfg_file.y" /* yacc.c:1906  */


int yyerror(char *s) 
{
   vtun_syslog(LOG_ERR, "%s line %d\n", s, lineno);
   return 0;
}

int cfg_error(const char *fmt, ...)
{
   char buf[255];
   va_list ap;

   /* print the argument string */
   va_start(ap, fmt);
   vsnprintf(buf,sizeof(buf),fmt,ap);
   va_end(ap);

   yyerror(buf);
   return 0;
}

int add_cmd(llist *cmds, char *prog, char *args, int flags)
{
   struct vtun_cmd *cmd;
   if( !(cmd = malloc(sizeof(struct vtun_cmd))) ){
      yyerror("No memory for the command");
      return -1;
   }
   memset(cmd, 0, sizeof(struct vtun_cmd)); 		   			

   cmd->prog = prog;
   cmd->args = args;
   cmd->flags = flags;
   llist_add(cmds, cmd);

   return 0;
}		

void *cp_cmd(void *d, void *u)
{
   struct vtun_cmd *cmd = d, *cmd_copy; 

   if( !(cmd_copy = malloc(sizeof(struct vtun_cmd))) ){
      yyerror("No memory to copy the command");
      return NULL;
   }
 
   cmd_copy->prog = strdup(cmd->prog);
   cmd_copy->args = strdup(cmd->args);
   cmd_copy->flags = cmd->flags;
   return cmd_copy;
}

int free_cmd(void *d, void *u)
{
   struct vtun_cmd *cmd = d; 
   free(cmd->prog);
   free(cmd->args);
   free(cmd);
   return 0;
}

void copy_addr(struct vtun_host *to, struct vtun_host *from)
{  
   if( from->src_addr.type ){
      to->src_addr.type = from->src_addr.type;
      to->src_addr.name = strdup(from->src_addr.name);
   }
   to->src_addr.port = from->src_addr.port;
}

void free_addr(struct vtun_host *h)
{  
   if( h->src_addr.type ){
      h->src_addr.type = 0;
      free(h->src_addr.name);
   }
}

int free_host(void *d, void *u)
{
   struct vtun_host *h = d;

   if (u && !strcmp(h->host, u))
      return 1;

   free(h->host);   
   free(h->passwd);   
   
   llist_free(&h->up, free_cmd, NULL);   
   llist_free(&h->down, free_cmd, NULL);

   free_addr(h);

   /* releases only host struct instances which were
    * allocated in the case of K_HOST except default_host */
   if( h->passwd )
      free(h);

 
   return 0;   
}

/* Find host in the hosts list.
 * NOTE: This function can be called only once since it deallocates hosts list.
 */ 
inline struct vtun_host* find_host(char *host)
{
   return (struct vtun_host *)llist_free(&host_list, free_host, host);
}

int clear_nat_hack_server(void *d, void *u)
{
	((struct vtun_host*)d)->flags &= ~VTUN_NAT_HACK_CLIENT;
	return 0;
}

int clear_nat_hack_client(void *d, void *u)
{
	((struct vtun_host*)d)->flags &= ~VTUN_NAT_HACK_SERVER;
	return 0;
}

/* Clear the VTUN_NAT_HACK flag which are not relevant to the current operation mode */
inline void clear_nat_hack_flags(int svr)
{
	if (svr)
		llist_trav(&host_list,clear_nat_hack_server,NULL);
	else 
		llist_trav(&host_list,clear_nat_hack_client,NULL);
}

inline void free_host_list(void)
{
   llist_free(&host_list, free_host, NULL);
}

static struct {
   char *c_name;
   int  c_val;
} syslog_names[] = {
    { "auth",   LOG_AUTH },
    { "cron",   LOG_CRON },
    { "daemon", LOG_DAEMON },
    { "kern",   LOG_KERN },
    { "lpr",    LOG_LPR },
    { "mail",   LOG_MAIL },
    { "news",   LOG_NEWS },
    { "syslog", LOG_SYSLOG },
    { "user",   LOG_USER },
    { "uucp",   LOG_UUCP },
    { "local0", LOG_LOCAL0 },
    { "local1", LOG_LOCAL1 },
    { "local2", LOG_LOCAL2 },
    { "local3", LOG_LOCAL3 },
    { "local4", LOG_LOCAL4 },
    { "local5", LOG_LOCAL5 },
    { "local6", LOG_LOCAL6 },
    { "local7", LOG_LOCAL7 },
    { NULL, -1 }
};

int parse_syslog(char *facility)
{
   int i;

   for (i=0; syslog_names[i].c_name;i++) {
      if (!strcmp(syslog_names[i].c_name, facility)) {
         vtun.syslog = syslog_names[i].c_val;
         return(0);
      }
   }
   return -1;
}

/* 
 * Read config file. 
 */ 
int read_config(char *file) 
{
   static int cfg_loaded = 0;
   extern FILE *yyin;

   if( cfg_loaded ){
      free_host_list();
      vtun_syslog(LOG_INFO,"Reloading configuration file");
   }	 
   cfg_loaded = 1;

   llist_init(&host_list);

   if( !(yyin = fopen(file,"r")) ){
      vtun_syslog(LOG_ERR,"Can not open %s", file);
      return -1;      
   }

   yyparse();

   free_host(&default_host, NULL);

   fclose(yyin);
  
   return !llist_empty(&host_list);     
}

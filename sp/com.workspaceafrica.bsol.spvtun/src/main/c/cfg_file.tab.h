/* A Bison parser, made by GNU Bison 3.0.2.  */

/* Bison interface for Yacc-like parsers in C

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
#line 67 "cfg_file.y" /* yacc.c:1909  */

   char *str;
   int  num;
   struct { int num1; int num2; } dnum;

#line 136 "cfg_file.tab.h" /* yacc.c:1909  */
};
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);

#endif /* !YY_YY_CFG_FILE_TAB_H_INCLUDED  */

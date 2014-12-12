/******************************************************************************
 *								              *	
 * JFree ARM Heap Analyzer						      *
 * 									      *
 * 	Julio Auto 			 <julio *noSPAM* julioauto.com>       *
 *	Rodrigo Rubira Branco (BSDaemon) <rodrigo *noSPAM* kernelhacking.com> *
 *****************************************************************************/

/***************************************************************************
 * ARM Stack Unwinder, Michael.McTernan.2001@cs.bris.ac.uk
 *
 * This program is PUBLIC DOMAIN.
 * This means that there is no copyright and anyone is able to take a copy
 * for free and use it as they wish, with or without modifications, and in
 * any context, commercially or otherwise. The only limitation is that I
 * don't guarantee that the software is fit for any purpose or accept any
 * liability for it's use or misuse - this software is without warranty.
 ***************************************************************************
 * File Description:  Unwinder client that reads local memory.
 **************************************************************************/

#ifndef CLIENT_H
#define CLIENT_H

/***************************************************************************
 * Nested Includes
 ***************************************************************************/

#include <stdio.h>
#include "unwarminder.h"

#if defined(SIM_CLIENT)
#error This file is not for the simulated unwinder client
#endif

/***************************************************************************
 * Typedefs
 ***************************************************************************/

/** Example structure for holding unwind results.
 */
typedef struct
{
    Int16 frameCount;
    Int32 address[32];
}
CliStack;

/***************************************************************************
 * Variables
 ***************************************************************************/

extern const UnwindCallbacks cliCallbacks;

/***************************************************************************
 * Macros
 ***************************************************************************/

#define UNWIND()                                                \
{                                                               \
    CliStack  results;                                          \
    Int8      t;                                                \
    Int32     sp;                                                \
    UnwResult r;                                                \
                                                                \
    (results).frameCount = 0;                                   \
    asm volatile("mov %0, $r13" : "=r" (sp));              \
    r = UnwindStart(sp, &cliCallbacks, &results);   \
                                                                \
    for(t = 0; t < (results).frameCount; t++)                   \
    {                                                           \
        printf("%c: 0x%08x\n",                                  \
               (results.address[t] & 0x1) ? 'T' : 'A',          \
               results.address[t] & (~0x1));                    \
    }                                                           \
                                                                \
    printf("\nResult: %d\n", r);                                \
}


#endif


/* END OF FILE */

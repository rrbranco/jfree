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
 * File Description: Implementation of the interface into the ARM unwinder.
 **************************************************************************/

#define MODULE_NAME "UNWARMINDER"

/***************************************************************************
 * Include Files
 **************************************************************************/

#include <system.h>
#if defined(UPGRADE_ARM_STACK_UNWIND)
#include <stdio.h>
#include <string.h>
#include "unwarminder.h"
#include "unwarm.h"


/***************************************************************************
 * Manifest Constants
 **************************************************************************/


/***************************************************************************
 * Type Definitions
 **************************************************************************/


/***************************************************************************
 * Variables
 **************************************************************************/


/***************************************************************************
 * Macros
 **************************************************************************/


/***************************************************************************
 * Local Functions
 **************************************************************************/


/***************************************************************************
 * Global Functions
 **************************************************************************/

typedef struct
{
    Int16 frameCount;
    Int32 address[32];
}
CliStack2;

UnwResult UnwindStart(Int32                  spValue,
                      const UnwindCallbacks *cb,
                      void                  *data)
{
    Int32    retAddr;
    UnwState state;

#if !defined(SIM_CLIENT)
    //retAddr = __return_address();
    asm volatile("mov %0, r14" : "=r" (retAddr));
#else
    retAddr = 0x0000a894;
    spValue = 0x7ff7edf8;
#endif

    /* Initialise the unwinding state */
    UnwInitState(&state, cb, data, retAddr, spValue);

    /* Check the Thumb bit */
    if(retAddr & 0x1)
    {
        return UnwStartThumb(&state);
    }
    else
    {
        return UnwStartArm(&state);
        //if ((((CliStack2*)data)->address[((CliStack2*)data)->frameCount-1] & 0x41568084) == 0x41568084)
        //    fprintf(stderr, "PC: %08x\n", state.regData[15].v);
        //return 0;
    }
}

#endif /* UPGRADE_ARM_STACK_UNWIND */

/* END OF FILE */

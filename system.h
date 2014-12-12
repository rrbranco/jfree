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
 **************************************************************************/
/** \file
 * Types common across the whole system.
 **************************************************************************/

#ifndef SYSTEM_H
#define SYSTEM_H

typedef unsigned char   Int8;
typedef unsigned short  Int16;
typedef unsigned int    Int32;


typedef signed char     SignedInt8;
typedef signed short    SignedInt16;
typedef signed int      SignedInt32;


typedef enum
{
    FALSE,
    TRUE
} Boolean;

#endif

/* END OF FILE */

#!/bin/bash

#/*****************************************************************************
# *								              *	
# * JFree ARM Heap Analyzer						      *
# * 									      *
# * 	Julio Auto 			 <julio *noSPAM* julioauto.com>       *
# *	Rodrigo Rubira Branco (BSDaemon) <rodrigo *noSPAM* kernelhacking.com> *
# *****************************************************************************/

if [ $# -lt 1 ]
then
    echo -e '\nUsage: '$0' <file.log>\n'
    exit 0
fi

echo -e '\nParsing log file '$1' for memory leaks\n'

TMPFILE=`mktemp jparsed.XXXXXX`

grep leaked $1 | grep -o ' top: 0x[^[:space:]]*' | grep -o '0x[^[:space:])]*' | sort | uniq -c | while read w1 w2; do echo -e $w1'\tmem leaks from '$w2' total: '`grep ' top: '$w2 $1 | grep -o '[0-9]* bytes' | perl -lne '$x += $_; END { print $x; }'`'\tbytes' >> $TMPFILE; done; grep -o ' [0-9]*[[:space:]]*bytes' $TMPFILE | sort -g | uniq | while read w1 w2; do grep ' '$w1'[[:space:]]*'$w2 $TMPFILE; done; rm $TMPFILE

echo -e '\nFinished parsing '$1'\n'

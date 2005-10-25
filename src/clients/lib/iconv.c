/*
 * iconv.c - conversion routine from locale to utf8.
 *
 * Copyright 2004,2005 - INL
 *	written by Eric Leblond <regit@inl.fr>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <iconv.h>
#include <langinfo.h>
#include <stdio.h>
#include <locale.h>
/* convert routine */

char * locale_to_utf8(char* inbuf){
	char* locale_charset=nl_langinfo(CODESET);
	iconv_t cd;
	size_t inlen=strlen(inbuf);
	char *outbuf,*targetbuf;
	size_t outbuflen=inlen*2+1;
	size_t outbufleft;
	int ret;

	setlocale (LC_ALL, "");
	/* iconv open */
	if (! locale_charset){
		printf("exit line %d\n",__LINE__);
		return NULL;
	}
	cd = iconv_open("UTF-8",locale_charset);
	/* iconv convert */
	outbuf=calloc(outbuflen,sizeof(char));
	if (!outbuf){
		printf("exit line %d\n",__LINE__);
		return NULL;
	}
	outbufleft=outbuflen;
	targetbuf=outbuf;
	ret = iconv (cd,&inbuf, &inlen,(char **)&targetbuf,&outbufleft);
	if (ret == -1){
		if (errno==E2BIG){
			/* TODO : put a good value here */
#define MAXBUF 512
			while((ret == -1) && (errno == E2BIG) &&(outbuflen < MAXBUF)){
				/* realloc outbuf */
				outbuflen+=inlen;
				outbuf=realloc(outbuf,outbuflen);
				if (outbuf){
					/* run iconv once more */
					outbufleft=outbuflen;
					targetbuf=outbuf;
					ret = iconv (cd,&inbuf, &inlen,&targetbuf,&outbufleft);
				} else {
					printf("exit line %d\n",__LINE__);
					return NULL;
				}
			}

		} else {
			free(outbuf);
			printf("exit line %d\n",__LINE__);
			iconv_close(cd);
			return NULL;
		}
	}
	/* iconv close */
	iconv_close(cd);
	/* realloc output to have a correct size */
	outbuf[outbuflen-outbufleft+1]=0;
	return realloc(outbuf,outbuflen-outbufleft+1);
}

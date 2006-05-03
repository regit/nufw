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
#include "libnuclient.h"

/**
 * \addtogroup libnuclient
 * @{
 */ 

/**
 * Convert a locale in locale charset to Unicode charset using UTF-8 encoding.
 * Maximum length of output buffer is four times of inbuf length.
 *
 * \param inbuf Input buffer written in locale charset
 * \return New allocated buffer, which need to be freed
 */
char* locale_to_utf8(char* inbuf)
{
    char* locale_charset;
    iconv_t ctx;
    size_t inlen=strlen(inbuf);
    size_t maxlen = inlen*4;
    char *outbuf;
    char *targetbuf;
    size_t real_outlen;
    size_t orig_inlen = inlen;
    size_t outbuflen=3;
    size_t outbufleft;
    int ret;

    /* get local charset */
    setlocale (LC_ALL, "");
    locale_charset=nl_langinfo(CODESET);
    nu_assert (locale_charset != NULL, "Can't get locale charset!");

    /* create an iconv context to convert locale charset to UTF-8 */
    ctx = iconv_open("UTF-8",locale_charset);

    /* allocate a buffer */
    outbuf=calloc(outbuflen,sizeof(char));
    nu_assert (outbuf != NULL, "iconv fail to allocate output buffer!");

    /* iconv convert */
    outbufleft=outbuflen-1; /* -1 because we keep last byte for nul byte */
    targetbuf=outbuf;
    ret = iconv (ctx, &inbuf, &inlen, &targetbuf, &outbufleft);
    real_outlen = targetbuf -outbuf; 
 
    /* is buffer too small? */
    if (ret == -1)
    {
        if (errno!=E2BIG)
        {
            free(outbuf);
            iconv_close(ctx);
            panic("iconv error code %i!", ret);
        }

        /* TODO : put a good value here */
        while((ret == -1) && (errno == E2BIG) &&(outbuflen < maxlen))
        {
            /* realloc outbuf */
            outbuflen+=orig_inlen;
            outbuf=realloc(outbuf,outbuflen);
            if (outbuf == NULL)
            {
                free(outbuf);
                iconv_close(ctx);
                panic("iconv error: can't rellocate buffer!");
            }

            /* run iconv once more */
            outbufleft=outbuflen - real_outlen - 1; /* -1 because we keep last byte for nul byte */
            targetbuf=outbuf + real_outlen;
            ret = iconv (ctx, &inbuf, &inlen, &targetbuf, &outbufleft);
            real_outlen = targetbuf -outbuf; 
        }
    }
    
    /* close iconv context */
    iconv_close(ctx);

    /* realloc output to have a correct size */
    outbuflen = real_outlen+1;
    outbuf = realloc(outbuf, outbuflen);
    outbuf[outbuflen-1]=0;
    return outbuf;
}

/** @} */

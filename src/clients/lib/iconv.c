/*
 ** Copyright 2004,2005 - INL
 ** Written by Eric Leblond <regit@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id$
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 2 of the License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
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
 * \param from_charset Target charset
 * \return New allocated buffer, which need to be freed
 */
char* nu_client_to_utf8(const char* inbuf, char *from_charset)
{
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

    /* just returns NULL if input is NULL */
    if (inbuf == NULL)
    {
        return inbuf;
    }

    /* create an iconv context to convert locale charset to UTF-8 */
    ctx = iconv_open("UTF-8", from_charset);

    /* allocate a buffer */
    outbuf=calloc(outbuflen,sizeof(char));
    nu_assert (outbuf != NULL, "iconv fail to allocate output buffer!");

    /* iconv convert */
    outbufleft=outbuflen-1; /* -1 because we keep last byte for nul byte */
    targetbuf=outbuf;
    ret = iconv (ctx, (char **)&inbuf, &inlen, &targetbuf, &outbufleft);
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
            ret = iconv (ctx, (char **)&inbuf, &inlen, &targetbuf, &outbufleft);
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

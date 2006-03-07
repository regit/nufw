#ifndef _NUFW_SECURITY_H
#define _NUFW_SECURITY_H

/** \def SECURE_STRNCPY(dst,src,size)
 * Copy string src to dst. Copy at maximum size-1 characters and make
 * sure that the string finish with a '\\0'.
 * 
 * Workaround strncpy security problem: if size is smaller than strlen(src),
 * dst doesn't contains '\\0'. This macro copy on maximum size-1 characters,
 * and always write a '\\0' on last position (dst[size-1]).
 */
#define SECURE_STRNCPY(dst, src, size) \
    do { strncpy(dst, src, (size)-1); (dst)[(size)-1] = '\0'; } while (0)

#endif   /* of ifndef _NUFW_SECURITY_H */

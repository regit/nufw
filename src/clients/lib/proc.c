#include <config.h>
#ifdef LINUX

#include "nuclient.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <paths.h>
#include <pwd.h>
#include <getopt.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <dirent.h>

#include "client.h"
#include "security.h"

/**
 * \addtogroup libnuclient
 * @{
 */

static struct prg_node {
    struct prg_node *next;     /** Pointer to next element in the single chained list */
    unsigned long inode;       /** Inode of the program executable binary */
    char name[PROGNAME_WIDTH]; /** Name of the program (encoded in UTF-8) */
} *prg_hash[PRG_HASH_SIZE];

#define PROGNAME_WIDTHs PROGNAME_WIDTH1(PROGNAME_WIDTH)
#define PROGNAME_WIDTH1(s) PROGNAME_WIDTH2(s)
#define PROGNAME_WIDTH2(s) #s

#define PRG_HASHIT(x) ((x) % PRG_HASH_SIZE)

#define PRG_LOCAL_ADDRESS "local_address"
#define PRG_INODE	 "inode"
#define PRG_SOCKET_PFX    "socket:["
#define PRG_SOCKET_PFXl (strlen(PRG_SOCKET_PFX))
#define PRG_SOCKET_PFX2   "[0000]:"
#define PRG_SOCKET_PFX2l  (strlen(PRG_SOCKET_PFX2))

#ifndef PATH_MAX
#  define PATH_MAX 4096
#endif

static void prg_cache_add(unsigned long inode, char *name)
{
    unsigned hi = PRG_HASHIT(inode);
    struct prg_node **pnp,*pn;

    prg_cache_loaded=2;
    for (pnp=prg_hash+hi;(pn=*pnp);pnp=&pn->next) {
	if (pn->inode==inode) {
	    /* Some warning should be appropriate here
	       as we got multiple processes for one i-node */
	    return;
	}
    }
    *pnp = malloc(sizeof(**pnp));
    if (*pnp == NULL)
	return;
    pn=*pnp;
    pn->next=NULL;
    pn->inode=inode;
    SECURE_STRNCPY(pn->name, name, sizeof(pn->name));
}

const char *prg_cache_get(unsigned long inode)
{
    unsigned hi=PRG_HASHIT(inode);
    struct prg_node *pn;

    for (pn=prg_hash[hi];pn;pn=pn->next)
	if (pn->inode==inode) return(pn->name);
    return("-");
}

void prg_cache_clear(void)
{
    struct prg_node **pnp,*pn;

    if (prg_cache_loaded == 2)
	for (pnp=prg_hash;pnp<prg_hash+PRG_HASH_SIZE;pnp++)
	    while ((pn=*pnp)) {
		*pnp=pn->next;
		free(pn);
	    }
    prg_cache_loaded=0;
}

static int extract_type_1_socket_inode(char lname[], unsigned long * inode_p)
{
    char *inode_str;
    char *serr;
    size_t len = strlen(lname);

    /* If lname is of the form "socket:[12345]", extract the "12345"
       as *inode_p.  Otherwise, return -1 as *inode_p.
       */
    if (len < PRG_SOCKET_PFXl+3) 
        return(-1);    
    if (memcmp(lname, PRG_SOCKET_PFX, PRG_SOCKET_PFXl)) 
        return(-1);
    if (lname[len-1] != ']') 
        return(-1);

    inode_str = lname + PRG_SOCKET_PFXl;
    lname[len-1] = '\0';
    *inode_p = strtol(inode_str,&serr,0);
    if (serr == NULL || *serr != '\0' || *inode_p >= INT_MAX)  {
        lname[len-1] = ']';
        printf("no %s\n", lname);
        return(-1);
    }
    lname[len-1] = ']';
    return(0);
}

static int extract_type_2_socket_inode(const char lname[], unsigned long * inode_p) {

    char *serr;

    /* If lname is of the form "[0000]:12345", extract the "12345"
       as *inode_p.  Otherwise, return -1 as *inode_p.
       */

    if (strlen(lname) < PRG_SOCKET_PFX2l+1) return(-1);
    if (memcmp(lname, PRG_SOCKET_PFX2, PRG_SOCKET_PFX2l)) return(-1);

    *inode_p=strtol(lname + PRG_SOCKET_PFX2l,&serr,0);
    if (serr == NULL || *serr != '\0' || *inode_p >= INT_MAX) 
        return(-1);
    return(0);
}

/**
 * Check if a string contains an integer
 *
 * \return 1 if it's a number, 0 otherwise
 */ 
int str_is_integer(const char* str)
{
    for (; *str != '\0'; ++str) 
    {
        if (!isdigit(*str)) 
            return 0;
    }
    return 1;
}

/**
 * Secure version of readlink()
 *
 * \return 0 if an error occurs, 1 if ok
 */
int secure_readlink(const char* filename, char *buffer, unsigned int buflen)
{
    int ret;

    /* call readlink (add 'canary' to check "buffer overflow") */
    buffer[buflen-1] = '\0';
    ret = readlink(filename, buffer, buflen);

    /* error if readlink fails */
    if (ret < 0)
        return 0;

    /* error if buffer is too small ("buffer overflow") */
    if (buffer[buflen-1] != '\0')
        return 0;

    /* that should never happens, but ... */
    if (((int)buflen-1) < ret)
        return 0;

    /* write nul byte at the end */
    buffer[ret] = '\0';
    return 1;
}

/**
 * Walk in directoty like "/proc/123/fd/" 
 */
void prg_cache_load_sub(DIR *dir, const char *path_process, const char *path_fd)
{
    char path[PATH_MAX];
    char lname[30];
    char finbuf[PROGNAME_WIDTH];
    unsigned long inode;
    struct dirent *file;

    while ((file = readdir(dir)) != NULL)
    {
#ifdef HAVE_STRUCT_DIRENT_D_TYPE
        if (file->d_type!=DT_LNK) 
            continue;
#endif

        /* read link of "/proc/123/fd/FILENAME" */
        if (!secure_snprintf(path, sizeof(path), "%s/%s", path_fd, file->d_name))
	    continue;
        if (!secure_readlink(path, lname, sizeof(lname)))
            continue;

        /*
         * extract inode number from name like "socket:[12345]" 
         * or "[0000]:12345" 
         */
        if (extract_type_1_socket_inode(lname, &inode) < 0)
            if (extract_type_2_socket_inode(lname, &inode) < 0)
                continue;

        /* get exec fullpath */
        if (!secure_snprintf(path, sizeof(path), "%s/exe", path_process))
	    continue;
        if (!secure_readlink(path, finbuf, sizeof(finbuf)))
            continue;

        /* add item to the cache */
        prg_cache_add(inode, finbuf);
    }
}

/**
 * Load program cache
 */
void prg_cache_load()
{
    char path_process[PATH_MAX];
    char path_fd[PATH_MAX];
    DIR *dirproc=NULL;
    DIR *dirfd=NULL;
    struct dirent *file;

    if (prg_cache_loaded) 
        return;
    prg_cache_loaded=1;
   
    /* open directory "/proc" */
    dirproc = opendir("/proc");
    if (dirproc == NULL) panic("Fail to open /proc directory!");

    while ( (file=readdir(dirproc)) != NULL )
    {
#ifdef HAVE_STRUCT_DIRENT_D_TYPE
	if (file->d_type!=DT_DIR)
	    continue;
#endif
	if (!str_is_integer(file->d_name))
	    continue;

	/* create path like "/proc/123" */
	if (!secure_snprintf(path_process, sizeof(path_process), "/proc/%s", file->d_name))
	    continue;

	/* create path like "/proc/123/fd" */
	if (!secure_snprintf(path_fd, sizeof(path_fd), "%s/fd", path_process))
	    continue;

	/* open directory like "/proc/123/fd" */
	dirfd = opendir(path_fd);
	if (dirfd != NULL) 
	{
	    prg_cache_load_sub(dirfd, path_process, path_fd);
	    closedir(dirfd); 
	}
    }
    closedir(dirproc);
}

/** @} */

#endif   /* of #ifdef LINUX */


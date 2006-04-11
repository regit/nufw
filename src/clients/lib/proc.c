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
#include <config.h>

#include "proc.h"
#include "security.h"

char * locale_to_utf8(char* inbuf);

static struct prg_node {
    struct prg_node *next;
    unsigned long inode;
    char name[PROGNAME_WIDTH];
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


#ifndef LINE_MAX
#define LINE_MAX 4096
#endif



#define PATH_PROC	   "/proc"
#define PATH_FD_SUFF	"fd"
#define PATH_FD_SUFFl       strlen(PATH_FD_SUFF)
#define PATH_PROC_X_FD      PATH_PROC "/%s/" PATH_FD_SUFF
#define PATH_EXE	"exe"
#define PATH_EXEl       strlen(PATH_EXE)
/* NOT working as of glibc-2.0.7: */
#undef  DIRENT_HAVE_D_TYPE_WORKS

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
    if (!(*pnp=malloc(sizeof(**pnp)))) 
	return;
    pn=*pnp;
    pn->next=NULL;
    pn->inode=inode;
#if USE_UTF8
	name=locale_to_utf8(name);
#endif
    if (strlen(name)>sizeof(pn->name)-1) 
	name[sizeof(pn->name)-1]='\0';
    strcpy(pn->name,name);
#if USE_UTF8
    free(name);
#endif
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

static int extract_type_1_socket_inode(const char lname[], unsigned long * inode_p) {

    /* If lname is of the form "socket:[12345]", extract the "12345"
       as *inode_p.  Otherwise, return -1 as *inode_p.
       */

    if (strlen(lname) < PRG_SOCKET_PFXl+3) return(-1);
    
    if (memcmp(lname, PRG_SOCKET_PFX, PRG_SOCKET_PFXl)) return(-1);
    if (lname[strlen(lname)-1] != ']') return(-1);

    {
        char inode_str[strlen(lname + 1)];  /* e.g. "12345" */
        const int inode_str_len = strlen(lname) - PRG_SOCKET_PFXl - 1;
        char *serr;

        strncpy(inode_str, lname+PRG_SOCKET_PFXl, inode_str_len);
        inode_str[inode_str_len] = '\0';
        *inode_p = strtol(inode_str,&serr,0);
        if (!serr || *serr || *inode_p >= INT_MAX) 
            return(-1);
    }
    return(0);
}



static int extract_type_2_socket_inode(const char lname[], unsigned long * inode_p) {

    /* If lname is of the form "[0000]:12345", extract the "12345"
       as *inode_p.  Otherwise, return -1 as *inode_p.
       */

    if (strlen(lname) < PRG_SOCKET_PFX2l+1) return(-1);
    if (memcmp(lname, PRG_SOCKET_PFX2, PRG_SOCKET_PFX2l)) return(-1);

    {
        char *serr;

        *inode_p=strtol(lname + PRG_SOCKET_PFX2l,&serr,0);
        if (!serr || *serr || *inode_p >= INT_MAX) 
            return(-1);
    }
    return(0);
}

int str_is_integer(const char* str)
{
    for (; *str != '\0'; ++str) 
    {
        if (!isdigit(*str)) 
            return 0;
    }
    return 1;
}

int secure_readlink(const char* filename, char *buffer, unsigned int buflen)
{
    int ret;

    /* call readlink (add 'canary' to check "buffer overflow") */
    buffer[buflen-1] = '\0';
    ret = readlink(filename, buffer, buflen-1);

    /* error if readlink fails */
    if (ret < 0)
        return 0;

    /* error if buffer is too small */
    if (buffer[buflen-1] != '\0')
        return 0;

    /* that should never happens, but ... */
    if ((buflen-1) < ret)
        return 0;

    /* write nul byte at the end */
    buffer[ret] = '\0';
    return 1;
}

void prg_cache_load(void)
{
    char line[LINE_MAX],eacces=0;
    int procfdlen,cmdllen,lnamelen;
    char lname[30],cmdlbuf[512],finbuf[PROGNAME_WIDTH];
    unsigned long inode;
    DIR *dirproc=NULL,*dirfd=NULL;
    struct dirent *direproc,*direfd;

    if (prg_cache_loaded ) return;
    prg_cache_loaded=1;
    cmdlbuf[sizeof(cmdlbuf)-1]='\0';
   
    dirproc = opendir(PATH_PROC);
    if (!dirproc) 
        goto fail;

    while (errno=0,direproc=readdir(dirproc)) {
#ifdef DIRENT_HAVE_D_TYPE_WORKS
	if (direproc->d_type!=DT_DIR) continue;
#endif
        if (!str_is_integer(direproc->d_name))
            continue;

	procfdlen=snprintf(line,sizeof(line),PATH_PROC_X_FD,direproc->d_name);
	if (procfdlen<=0 || procfdlen>=((int)sizeof(line)-5)) 
	    continue;
        
	errno=0;
	dirfd=opendir(line);
	if (! dirfd) {
	    if (errno==EACCES) 
		eacces=1;
	    continue;
	}
        
	line[procfdlen] = '/';
	while ((direfd = readdir(dirfd))) {
#ifdef DIRENT_HAVE_D_TYPE_WORKS
	    if (direfd->d_type!=DT_LNK) 
		continue;
#endif
	    if (procfdlen+1+strlen(direfd->d_name)+1>sizeof(line)) 
		continue;
	    memcpy(line + procfdlen - PATH_FD_SUFFl, PATH_FD_SUFF "/",
		   PATH_FD_SUFFl+1);
	    strcpy(line + procfdlen + 1, direfd->d_name);

            if (!secure_readlink(line, lname, sizeof(lname)))
                continue;

            if (extract_type_1_socket_inode(lname, &inode) < 0)
              if (extract_type_2_socket_inode(lname, &inode) < 0)
                continue;

            if (procfdlen - PATH_FD_SUFFl + PATH_EXEl >= 
                    sizeof(line) - 5) 
                continue;
            strcpy(line + procfdlen-PATH_FD_SUFFl, PATH_EXE);

            if (!secure_readlink(line, cmdlbuf, sizeof(cmdlbuf)))
                continue;
	    
	    SECURE_STRNCPY(finbuf, cmdlbuf, sizeof(finbuf));
	    prg_cache_add(inode, finbuf);
	}
	closedir(dirfd); 
	dirfd = NULL;
    }
    if (dirproc) 
	closedir(dirproc);
    if (dirfd) 
	closedir(dirfd);
    if (!eacces) 
	return;
    if (prg_cache_loaded == 1) {
    fail:
	fprintf(stderr,"(No info could be read for \"-p\": geteuid()=%d but you should be root.)\n",
		geteuid());
    }
}
#endif   /* of #ifdef LINUX */


/* pam_nufw module */

/*
 * pam_nufw.c PAM module auth client
 * 
 * Written by Jean Gillaux <jean@inl.fr>
 * Based on pam_permit by Andrew Morgan <morgan@parc.power.net> 1996/3/11
 *
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


#define _GNU_SOURCE
#include "../lib/nuclient.h"
#include <stdio.h>
#include <syslog.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>

/*
 * here, we make definitions for the externally accessible functions
 * in this file (these definitions are required for static modules
 * but strongly encouraged generally) they are used to instruct the
 * modules include file to define their prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/_pam_macros.h>


#define NUAUTH_SRV "192.168.12.1"
#define NUAUTH_PORT 4130
#define FILE_LOCK ".pam_nufw"

#define DEFAULT_USER "nobody"
#define MAX_RETRY_TIME 30

char* glob_pass; 
char* glob_user;
struct pam_nufw_s pn_s;

/* internal data */
struct pam_nufw_s {
    char nuauth_srv[BUFSIZ]; /* auth server to connect to */
    int nuauth_port;  /* port to use on auth server */
    char file_lock[BUFSIZ]; /* file lock used to store pid */
};


/* Callback functions for libnuclient */
char* get_password(){
    return glob_pass;
}

char* get_username(){
    return glob_user;
}

/* init pam_nufw info struct */
static void _init_pam_nufw_s(struct pam_nufw_s *pn_s){
    memset(pn_s, 0, sizeof(pn_s));
    strncpy(pn_s->nuauth_srv,NUAUTH_SRV, sizeof(pn_s->nuauth_srv)-1);
    pn_s->nuauth_port = NUAUTH_PORT;
    strncpy(pn_s->file_lock,FILE_LOCK, sizeof(pn_s->file_lock)-1);
}

/*  function to parse arguments */
static int _pam_parse(int argc, const char** argv, struct pam_nufw_s *pn){
    int ctrl = 0;
    for(ctrl=0; argc-- > 0; ++argv){
        if(!strncmp(*argv,"server=",7)) {
            strncpy(pn->nuauth_srv,*argv + 7, sizeof(pn->nuauth_srv)-1);
        }else if(!strncmp(*argv, "port=",5)){
            pn->nuauth_port = atoi(*argv + 5);
        }else if(!strncmp(*argv, "lock=", 5)){
            strncpy(pn->file_lock,*argv + 5, sizeof(pn->file_lock)-1);
        }
    }
    return ctrl;
}

char * _get_runpid(struct pam_nufw_s *pn_s){
    char path_dir[254];
    char *home = getenv("HOME");
    if (home == NULL)
        return NULL;            
    snprintf(path_dir,sizeof(path_dir),"%s/.nufw", home);
    if (access(path_dir,R_OK)){
        mkdir(path_dir,S_IRWXU);
    }
    snprintf(path_dir, sizeof(path_dir), "%s/.nufw/%s", home, pn_s->file_lock);
    return (char*) (strdup(path_dir));
    /*return strdup(path_dir);*/
}

static int _kill_nuclient(char *runpid){
    pid_t pid;
    FILE* FD;
    int ok, ret;

    if (runpid){
        FD = fopen(runpid,"r");
        if (FD){
            fscanf(FD,"%d",&pid);
            fclose(FD);
            ret = kill(pid,SIGTERM);
            ok = (ret == 0);
            if (ok) {
                /*printf("nutcpc process killed (pid %lu)\n", (unsigned long)pid);*/
                return 0;
            } else {
                printf("Fail to kill process: remove pid file\n");
                unlink(runpid);
                return 1;
            }
        }
        free(runpid);
    }
    return 0;
}

/* function used to kill client */
void exit_client(){
    char* runpid;
    runpid = _get_runpid(&pn_s);
    if(runpid != NULL){
        unlink(runpid);
        free(runpid);
    }
    exit(EXIT_SUCCESS);
}


/* --- authentication management functions --- */

/*
 * used to open the connection to the nuauth server
 */

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc
        ,const char **argv)
{
  int retval = PAM_AUTH_ERR;
  int p;
  struct sigaction no_action;
  const char *user = NULL;
  const char *password = NULL;
  int uid,gid=0;
  NuAuth *session;
  struct passwd *pw;
  unsigned long interval = 100;
  int tempo = 1;
  int pdesc[2];
  int ctrl;
  nuclient_error *err=NULL;

  _init_pam_nufw_s(&pn_s);

  /*D(("(pam_nufw) sm_authenticate"));*/
  syslog(LOG_ERR,"pam_nufw authenticate");
  ctrl = _pam_parse(argc, argv, &pn_s);
  /*
   * authentication requires we know who the user wants to be
   */
  retval = pam_get_user(pamh, &user, NULL);
  if (retval != PAM_SUCCESS) {
      syslog(LOG_ERR,"get user returned error: %s", pam_strerror(pamh,retval));
      return retval;
  }
  if (user == NULL || *user == '\0') {
      pam_set_item(pamh, PAM_USER, (const void *) DEFAULT_USER);
  }

  if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password) == PAM_SUCCESS){
#ifdef DEBUG
      /*syslog(LOG_INFO, "(pam_nufw) got password %s.",password);*/
#endif
      if (password == NULL)
          syslog(LOG_ERR, "(pam_nufw) password is NULL!");
  }else{
      syslog(LOG_ERR, "pam_nufw failed to get password");
  }

  /*syslog(LOG_INFO,"(pam_nufw) connect nuauth: srv=%s, port=%i",srv_addr,port);*/
  pw = (struct passwd *)getpwnam(user);
  uid = (uid_t)(pw->pw_uid);
  gid = getgid();
  /*syslog(LOG_INFO,"(pam_nufw) uid=%i, gid=%i",uid,gid);*/
  setenv("HOME",pw->pw_dir,1);
  glob_pass = (char*)password;
  glob_user = (char*)user;

  if (pipe(pdesc) == -1){
      syslog(LOG_ERR,"pipe failed %s",strerror(errno));
  }
  p = fork();
  if (p < 0){
      syslog(LOG_ERR, "(pam_nufw) fork failed");
      return PAM_AUTH_ERR;
  }
  if (p == 0){/* in child */
      /*syslog(LOG_INFO,"(pam_nufw) in child");*/
      setuid(uid);
      /*syslog(LOG_INFO,"(pam_nufw) child uid %i",getuid());*/
      /* signal management */
      no_action.sa_handler = exit_client;
      sigemptyset( & (no_action.sa_mask));
      no_action.sa_flags = 0;
      if ( sigaction( SIGINT, & no_action , NULL ) != 0) {
          syslog(LOG_ERR, "Erro setting sigaction");
          return PAM_AUTH_ERR;
      }
      if ( sigaction( SIGTERM, & no_action , NULL ) != 0) {
          syslog(LOG_ERR, "Erro setting sigaction");
          return PAM_AUTH_ERR;
      }

      /* libnuclient init function */
      nu_client_global_init(err);
      session = nu_client_init2(
              pn_s.nuauth_srv,
              pn_s.nuauth_port,
              NULL,
              NULL,
              &get_username,
              &get_password,
              NULL,
              err
              );
      /*syslog(LOG_INFO,"(pam_nufw) after nu_client_init2");*/
      if(session == NULL){
          syslog(LOG_ERR,"(pam_nufw) Cannot connect to NuAuth Server");
          int nerror = errno;
          syslog(LOG_ERR,"(pam_nufw) Problem : %s\n",strerror(nerror));
          /*return PAM_AUTH_ERR;*/
          return PAM_SUCCESS;
      }else{
          /* session opened to nuauth */
          syslog(LOG_INFO,"(pam_nufw) session to NuAuth server open, username=%s, server=%s",session->username,pn_s.nuauth_srv);
          /* write pid in lockfile */
          int mypid;
          FILE* RunD;
          mypid = getpid();
          RunD=fopen(_get_runpid(&pn_s),"w");
          fprintf(RunD,"%d",mypid);
          fclose(RunD);
          for (;;) {
              usleep (interval * 1000);
              if (session == NULL){
                  sleep(tempo);
                  if (tempo< MAX_RETRY_TIME) {
                      tempo=tempo*2;
                  }
                  session = nu_client_init2(
                          pn_s.nuauth_srv,
                          pn_s.nuauth_port,
                          NULL,
                          NULL,
                          &get_username,
                          &get_password,
                          NULL,
                          err
                          );
                  if (session!=NULL){
                      tempo=1;
                  }
              } else {
                  if (nu_client_check(session,err)<0){
                      session=NULL;
                  }
              }
          }



      }
  }else{ /* in parent */
      /* nothing to do */
      /*syslog(LOG_INFO,"(pam_nufw) in parent");*/
  }
  user = NULL;                                            /* clean up */
  /*syslog(LOG_INFO,"(pam_nufw) exiting...");*/
  return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc
        ,const char **argv)
{
  /*D(("pam_nufw sm_setcred"));*/
  return PAM_SUCCESS;
}

/* --- account management functions --- */

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh,int flags,int argc
        ,const char **argv)
{
  D(("pam_nufw sm_acct_mgmt"));
  return PAM_SUCCESS;
}

/* --- password management --- */

PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc
        ,const char **argv)
{
  D(("pam_nufw sm_chauthok"));
  return PAM_SUCCESS;
}

/* --- session management --- */

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh,int flags,int argc
        ,const char **argv)
{
  /*const char *password = NULL; */
  /*D(("pam_nufw sm_open_session"));*/
  /*pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
    syslog(LOG_INFO, "(pam_nufw) passwd: %s",password);*/
  syslog(LOG_INFO,"(pam_nufw) session opened");
  return PAM_SUCCESS;
}

/* 
 * On session closing, we want to close the connection
 * -> get pid file, and kill process
 */
PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh,int flags,int argc
        ,const char **argv)
{
  /*D(("pam_nufw sm_close_session"));*/
  int ctrl;
  struct passwd *pw;
  const char* user = NULL;
  int retval;

  /* get parameters */
  _init_pam_nufw_s(&pn_s);
  /*syslog(LOG_INFO, "(pam_nufw) file_lock: %s",pn_s.file_lock);*/
  ctrl = _pam_parse(argc, argv, &pn_s);

  /* get username */
  retval = pam_get_user(pamh, &user, NULL);

  pw = (struct passwd *)getpwnam(user);
  setenv("HOME",pw->pw_dir,1);
  /*syslog(LOG_INFO, "(pam_nufw) file_lock: %s",_get_runpid(&pn_s));*/

  /* kill client */
  _kill_nuclient(_get_runpid(&pn_s));

  syslog(LOG_INFO, "(pam_nufw) session closed");
  return PAM_SUCCESS;
}

/* end of module definition */

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_permit_modstruct = {
    "pam_nufw",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};

#endif

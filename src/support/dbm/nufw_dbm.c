/*
 ** Copyright(C) 2004 Vincent Deffontaines <vincent@inl.fr>
                       INL
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation; version 2 of the License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 ** In addition, as a special exception, the copyright holders give
 ** permission to link the code of portions of this program with the
 ** Cyrus SASL library under certain conditions as described in each
 ** individual source file, and distribute linked combinations
 ** including the two.
 ** You must obey the GNU General Public License in all respects
 ** for all of the code used other than Cyrus SASL.  If you modify
 ** file(s) with this exception, you may extend this exception to your
 ** version of the file(s), but you are not obligated to do so.  If you
 ** do not wish to do so, delete this exception statement from your
 ** version.  If you delete this exception statement from all source
 ** files in the program, then also delete it here.
 **
 ** This product includes software developed by Computing Services
 ** at Carnegie Mellon University (http://www.cmu.edu/computing/).
 **
 ** */

#define _GNU_SOURCE

#include <termios.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <gdbm.h>

#include <sasl/saslutil.h>
#include <gcrypt.h>

#define MODE_LIST 1
#define MODE_DELETE 2
#define MODE_CREATE 3
#define MODE_UPDATE 4
#define MODE_REORG 5

#define CRYPT_MD5 1
#define CRYPT_SHA1 2

void usage (char *program_name)
{
  fprintf (stderr, "Usage:\n");
  fprintf (stderr, "%s <GDBM users file>                                                   (list usernames)\n",program_name);
  fprintf (stderr, "%s [-P] -l username <GDBM users file>                                  (show username's entry)\n",program_name);
  fprintf (stderr, "%s -d username <GDBM users file>                                       (delete user)\n",program_name);
  fprintf (stderr, "%s [-C SHA1/MD5] [-o] [-r] -c username -g <UID>,<gid>[,<gid>...] <GDBM file> (create user)\n",program_name);
  fprintf (stderr, "%s -u username <GDBM users file>                                       (update user's password)\n",program_name);
  fprintf (stderr, "%s -R <GDBM users file>                                                (reorganize database)\n",program_name);
}

void check_mode(int mode, char *s)
{
   if (mode > 0)
   {
     usage(s);
     exit(1);
   }
}

void fatal_e(char *msg)
{
  fprintf(stderr,"A fatal error occured : %s\n",msg);
  exit(1);
}

/* IN : password in a string, gids in the form "gid1,gid2,..."
 * OUT : DBM stored format : "password gid1 gid2 ... " Yes there IS a space in
 * the end of the output string. */
void pass_and_gids(char *passwd, char *gids, char **result)
{
  char *tmp;
  *result = (char *)calloc(strlen(passwd) + strlen(gids) +3 ,sizeof(char));
  if (*result == NULL)
      fatal_e("Could not malloc!");
  sprintf(*result,"%s ",passwd);
  tmp = strtok(gids,",");
  while (tmp != NULL)
  {
    strcat(*result,tmp);
    strcat(*result," ");
    tmp = strtok(NULL,",");
  }
}

int prompt_password(char **pass1, size_t *n)
{
  struct termios orig, new;
  char *pass2=NULL;
  char *pass0=NULL;
  if (tcgetattr (fileno (stdin), &orig) != 0)
  {
      free(pass2);
      return -1;
  }
  new = orig;
  new.c_lflag &= ~ECHO;
  if (tcsetattr (fileno (stdin), TCSAFLUSH, &new) != 0)
  {
      return -1;
  }
  printf("Password:");
  getline (&pass0, n, stdin);
  printf("\nPlease retype password:");
  getline (&pass2, n, stdin);

  printf("\n");

  tcsetattr (fileno (stdin), TCSAFLUSH, &orig);
  if (strcmp(pass0,pass2) != 0)
  {
    free(pass0);
    free(pass2);
    fprintf(stderr,"Sorry. Passwords do not match!\n");
    exit(0);
  }
  free(pass0);
  if (strlen(pass2)<=1)
  {
    fprintf(stderr,"Sorry. Empty password not acceptable!\n");
    exit(0);
  }
  *pass1=pass2;
  return 0;
}

int passwd_crypt(int pass_crypt,char **pass)
{
  gcry_md_hd_t hd;
  unsigned char *crypted;
  char *prestring;
  char decoded[30];
  int algo = 0;
  size_t len;
  if (pass_crypt == 0)
      return 0;
  /* MD5 */
  if (pass_crypt == CRYPT_SHA1)
  {
      algo = GCRY_MD_SHA1;
      prestring="{SHA1}";
  }
  else if (pass_crypt == CRYPT_MD5)
  {
      algo = GCRY_MD_MD5;
      prestring="{MD5}";
  }else{
      return -1;
  }
   gcry_md_open (&hd, algo,0);
   gcry_md_write(hd,*pass,strlen(*pass));
   crypted=gcry_md_read(hd,algo);
   sasl_encode64((char *)crypted,strlen((char *)crypted),decoded,30,&len);
   free(*pass);
   *pass = (char *)calloc(36,sizeof(char));
   if (*pass == NULL)
       fatal_e("Could not malloc");
   sprintf(*pass,"%s%s",prestring,decoded);
   return 0;
}

int main(int argc, char *argv[])
{
  char *program_name = argv[0];
  char *username=NULL;
  char *filename;
  char *groups=NULL;
  int mode=0;
  int override=0;
  int replace=0;
  int show_pass = 0;
  int pass_crypt = 0;
  int ch;
  datum key;
  GDBM_FILE dbf;
  while ((ch = getopt (argc, argv, "RProl:d:c:u:g:C:")) != -1) 
  {
      switch (ch) {
        case 'C':
          if (!strcmp(optarg,"SHA1"))
            pass_crypt = CRYPT_SHA1;
          else if(!strcmp(optarg,"MD5"))
            pass_crypt = CRYPT_MD5;
          else
            usage(program_name);
          break;
        case 'P':
          show_pass = 1;
          break;
        case 'o':
          override = 1;
          break;
        case 'r':
          replace = 1;
          break;
        case 'R':
          check_mode(mode,program_name);
          mode = MODE_REORG;
          break;
        case 'l':
          check_mode(mode,program_name);
          username = optarg;
          mode = MODE_LIST;
          break;
        case 'd':
          check_mode(mode,program_name);
          username = optarg;
          mode = MODE_DELETE;
          break;
        case 'c':
          check_mode(mode,program_name);
          username = optarg;
          mode = MODE_CREATE;
          break;
        case 'g':
          groups = optarg;
          break;
        case 'u':
          check_mode(mode,program_name);
          username = optarg;
          mode = MODE_UPDATE;
          break;
        default:
          usage(program_name);
          exit(1);
      }
  }     
  if (optind < argc)
  {
      filename = argv[optind];
  }else{
      usage(program_name);
      exit(1);
  }
  /* Listing mode */
  if ((mode == 0) || (mode == MODE_LIST))
  {
    datum data;
    char *tmp;
    dbf = gdbm_open(filename, 512, GDBM_READER, 0, 0);
    if (dbf == NULL)
        fatal_e(gdbm_strerror ( gdbm_errno ));
    /* One user only */
    if (mode == MODE_LIST)
    {
        key.dsize = strlen(username);
        key.dptr = username;
        if (!gdbm_exists(dbf,key))
        {
            fprintf(stderr,"Sorry, no user named '%s'\n",username);
            exit (0);
        }
        data = gdbm_fetch(dbf,key);
        if (data.dptr == NULL)
        {
            fprintf(stderr,"Sorry, no data was found for '%s'\n",username);
            exit(0);
        }
        tmp = strtok(data.dptr," ");
        if (show_pass)
        {
            printf("%s ",tmp);
        }
        tmp = strtok(NULL," ");
        while (tmp != NULL)
        {
          printf("%s ",tmp);
          tmp = strtok(NULL," ");
        }
        printf("\n");
        free(data.dptr);
        return 0;
    } else {
    /* All users */
      key = gdbm_firstkey ( dbf );
      while (key.dptr != NULL)
      {
        printf("%s\n",key.dptr);
        datum nextkey;
        nextkey = gdbm_nextkey ( dbf, key );
        free(key.dptr);
        key = nextkey;
      }
      free(key.dptr);
      gdbm_close(dbf);
      return 0;
    }
  }
  /* Create a new user */
  else if (mode == MODE_CREATE)
  {
    int ret;
    datum data;
    char *inserted;
    char *pass1=NULL;
    size_t pass_size = 0;
    if (groups == NULL)
    {
        usage(program_name);
        free(pass1);
        exit(1);
    }
    if (prompt_password(&pass1,&pass_size) != 0)
        fatal_e("An error occured when reading password\n");

	if (strlen(pass1)<pass_size) {
		pass1[strlen(pass1)-1]=0;
	}

    passwd_crypt(pass_crypt,&pass1);
    if (override)
    {
      dbf = gdbm_open(filename, 512, GDBM_NEWDB, 0600, 0);
    }
    else
    {
      dbf = gdbm_open(filename, 512, GDBM_WRCREAT, 0600, 0);
    }
    if (dbf == NULL)
    {
        free(pass1);
        fatal_e(gdbm_strerror ( gdbm_errno ));
    }
    pass1=strtok(pass1,"\n");
    pass_and_gids(pass1,groups,&inserted);
    free(pass1);
    data.dsize=strlen(inserted);
    data.dptr= inserted;
    key.dsize=strlen(username);
    key.dptr=username;
    if (replace)
    {
        ret = gdbm_store(dbf,key,data,GDBM_REPLACE);
    }
    else
    {
        ret = gdbm_store(dbf,key,data,GDBM_INSERT);
    }
    gdbm_close(dbf);
    free(inserted);
    if (ret==1)
    {
      fprintf(stderr,"Looks like user %s already exists! (Use '-r' to override)\n",username);
      exit(1);
    }
    if (ret!=0)
    {
      fprintf(stderr,"An error occured when adding user %s\n",username);
      exit(1);
    }
    return 0;
  }
  /* Other modes : update user, delete user */
  else 
  {
    dbf = gdbm_open(filename, 512, GDBM_WRITER, 0, 0);
    if (dbf == NULL)
        fatal_e(gdbm_strerror ( gdbm_errno ));
    if (mode == MODE_DELETE)
    {
        int ret;
        key.dsize = strlen(username);
        key.dptr = username;
        ret = gdbm_delete(dbf,key);
        if (ret != 0)
        {
            fprintf(stderr,"Sorry, user %s could not be deleted!\n",username);
            gdbm_close(dbf);
            exit (1);
        }
        gdbm_close(dbf);
        return 0;
    }else if (mode == MODE_UPDATE)
    {
        char *pass=NULL;
        size_t size=32;
        int ret;
        char *chaine;
        pass_crypt = 0;
        datum data, insert;
        key.dsize = strlen(username);
        key.dptr = username;
        if (! gdbm_exists(dbf,key))
        {
            fprintf(stderr,"Sorry. No user named %s was found\n",username);
            exit(1);
        }
        data=gdbm_fetch(dbf,key);
        if (data.dptr == NULL)
        {
            fprintf(stderr,"Sorry. Could not retreive data for user %s\n",username);
            exit(1);
        }
        chaine = strchr(data.dptr,' ');
        if (!strncmp(data.dptr,"{SHA1}",6))
            pass_crypt = CRYPT_SHA1;
        else if (!strncmp(data.dptr,"{MD5}",5))
            pass_crypt = CRYPT_MD5;

        if (prompt_password(&pass,&size) != 0)
            fatal_e("prompt_password error");
        pass=strtok(pass,"\n");
        passwd_crypt(pass_crypt,&pass);
        insert.dptr=(char *)calloc(sizeof(char)*(strlen(pass)+strlen(chaine)+1),sizeof(char));
        if (insert.dptr == NULL)
            fatal_e("Could not malloc!");
        sprintf(insert.dptr,"%s%s",pass,chaine);
        insert.dsize = strlen(pass)+strlen(chaine)+1;
        free(data.dptr);
        ret = gdbm_store(dbf,key,insert,GDBM_REPLACE);
        if (ret != 0)
            fatal_e("Could not replace password");
        gdbm_close(dbf);
        return 0;
    }else if (mode == MODE_REORG)
    {
        if (gdbm_reorganize(dbf) != 0)
        {
          fprintf(stderr,"An error occured while reorganizing : %s",gdbm_strerror ( gdbm_errno ));
          exit(1);
        }
    }else{
        fprintf(stderr,"Sorry, unknown operation\n");
        exit(1);
    }
  }
  return(0);
}


/*
 * Copyright(C) 2004 INL
 ** written by  Eric Leblond <eric@inl.fr>
 **             Vincent Deffontaines <vincent@inl.fr>
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

#define _GNU_SOURCE
#include <auth_srv.h>
#include <proto.h>
#include <crypt.h>
#include <sys/time.h>

#if 0
struct up_datas {
    u_int32_t ip_client;
    char * dgram;
};
#endif

void* user_authsrv(){
    int z;
    int sck_inet;
    struct sockaddr_in addr_inet,addr_clnt;
    int len_inet;
    char dgram[512];
#if 0
    struct up_datas userdatas;
#endif

    //open the socket
    sck_inet = socket (AF_INET,SOCK_DGRAM,0);

    if (sck_inet == -1)
    {
        g_error("socket()");
        exit(-1);
    }

    memset(&addr_inet,0,sizeof addr_inet);

    addr_inet.sin_family= AF_INET;
    addr_inet.sin_port=htons(userpckt_port);
    addr_inet.sin_addr.s_addr=client_srv.sin_addr.s_addr;

    len_inet = sizeof addr_inet;

    z = bind (sck_inet,
        (struct sockaddr *)&addr_inet,
        len_inet);
    if (z == -1)
    {
        g_error ("user bind()");
        exit(-1);
    }


    for(;;){
        char *datas;
        len_inet = sizeof addr_clnt;
        z = recvfrom(sck_inet,
            dgram,
            sizeof dgram,
            0,
            (struct sockaddr *)&addr_clnt,
            &len_inet);
        if (z<0)
        {
            g_warning("user_pckt recvfrom()");
            continue;
            // exit(-1); /*useless*/
        }
        /* copy packet datas */
        datas=g_new0(char,z);
        memcpy(datas,dgram,z);
        /* and send packet to thread */
        g_thread_pool_push (user_checkers,
            datas,	
            NULL
            );
    }
    close(sck_inet);

    return NULL;
}

static int
treat_user_request (SSL* rx){
    char * buf;

    /* copy packet datas */
    buf=g_new0(char,64);
    if ( SSL_read(rx,buf,63) > 0 ){
        g_thread_pool_push (user_checkers,
            buf,	
            NULL
            );
    } else {
        return EOF;
    }
    return 1;
}


int sck_inet;

void ssl_nuauth_cleanup( int signal ) {
    /* close socket */
    close(sck_inet);
    /* exit */
    exit(0);
}

/*
 * SSL user packet server
 */

void* ssl_user_authsrv(){
    int z;
    struct sigaction action;
    struct sockaddr_in addr_inet,addr_clnt;
    int len_inet;
    int mx,n,c,r;
    fd_set rx_set; /* read set */
    fd_set wk_set; /* working set */
    struct timeval tv;
    FILE* c_stream;
    SSL* ssl;
    SSL_CTX* ctx;
    BIO* sbio;
    gpointer vpointer;
    char *configfile=DEFAULT_CONF_FILE;
    char* nuauth_ssl_key=NUAUTH_KEYFILE;
    char* nuauth_ssl_key_passwd=NUAUTH_KEY_PASSWD;
    confparams nuauth_ssl_vars[] = {
        { "nuauth_ssl_key" , G_TOKEN_STRING , 0, NUAUTH_KEYFILE },
        { "nuauth_ssl_key_passwd" , G_TOKEN_STRING , 0, NUAUTH_KEY_PASSWD },
        { "nuauth_ssl_max_clients" , G_TOKEN_INT ,NUAUTH_SSL_MAX_CLIENTS, NULL }
    };
    GArray* client;
    int nuauth_ssl_max_clients=NUAUTH_SSL_MAX_CLIENTS;
#if 0
    struct up_datas userdatas;
#endif
    /* get config file setup */
    /* parse conf file */
    parse_conffile(configfile,sizeof(nuauth_ssl_vars)/sizeof(confparams),nuauth_ssl_vars);
    /* set variable value from config file */
    vpointer=get_confvar_value(nuauth_ssl_vars,sizeof(nuauth_ssl_vars)/sizeof(confparams),"nuauth_ssl_key");
    nuauth_ssl_key=(char*)(vpointer?vpointer:nuauth_ssl_key);
    vpointer=get_confvar_value(nuauth_ssl_vars,sizeof(nuauth_ssl_vars)/sizeof(confparams),"nuauth_ssl_key_passwd");
    nuauth_ssl_key_passwd=(char*)(vpointer?vpointer:nuauth_ssl_key_passwd);
    vpointer=get_confvar_value(nuauth_ssl_vars,sizeof(nuauth_ssl_vars)/sizeof(confparams),"nuauth_ssl_max_clients");
    nuauth_ssl_max_clients=*(int*)(vpointer?vpointer:&nuauth_ssl_max_clients);

    /* build array client */
    client = g_array_new (FALSE, TRUE, sizeof (SSL*)); 
    client = g_array_set_size(client,nuauth_ssl_max_clients);
    /* Build our SSL context*/
    ctx=initialize_ctx(nuauth_ssl_key,nuauth_ssl_key_passwd);
    /* TODO */
    //load_dh_params(ctx,DHFILE);
    //
    //
    /* intercept SIGTERM */
    action.sa_handler = ssl_nuauth_cleanup;
    sigemptyset( & (action.sa_mask));
    action.sa_flags = 0;
    if ( sigaction( SIGTERM, & action , NULL ) != 0) {
        printf("Error\n");
        exit(1);
    }

    //open the socket
    sck_inet = socket (AF_INET,SOCK_STREAM,0);

    if (sck_inet == -1)
    {
        g_error("socket()");
        exit(-1);
    }

    memset(&addr_inet,0,sizeof addr_inet);

    addr_inet.sin_family= AF_INET;
    addr_inet.sin_port=htons(userpckt_port);
    addr_inet.sin_addr.s_addr=client_srv.sin_addr.s_addr;

    len_inet = sizeof addr_inet;

    z = bind (sck_inet,
        (struct sockaddr *)&addr_inet,
        len_inet);
    if (z == -1)
    {
        g_error ("user bind()");
        exit(-1);
    }

    /* Listen ! */
    z = listen(sck_inet,20);
    if (z == -1)
    {
        g_error ("user listen()");
        exit(-1);
    }

    /* init fd_set */
    FD_ZERO(&rx_set);
    FD_ZERO(&wk_set);
    FD_SET(sck_inet,&rx_set);
    mx=sck_inet+1;

    for(;;){

        /*
         * copy rx set to working set 
         */

        for (z=0;z<mx;++z){
            if (FD_ISSET(z,&rx_set))
                FD_SET(z,&wk_set);
        }

        /*
         * define timeout 
         */

        tv.tv_sec=2;
        tv.tv_usec=30000;

        n=select(mx,&wk_set,NULL,NULL,&tv);

        if (n == -1) {
            g_warning("select\n");
            exit(1);
        } else if (!n) {
            continue;
        }

        /*
         * Check if a connect has occured
         */

        if (FD_ISSET(sck_inet,&wk_set) ){
            /*
             * Wait for a connect
             */
            len_inet = sizeof addr_clnt;
            c = accept (sck_inet,
                (struct sockaddr *)&addr_clnt,
                &len_inet);
            if (c == -1)
                g_warning("accept");

            if ( c >= nuauth_ssl_max_clients) {
                close(c);
                continue;
            }

            /*
             * create stream
             */

            c_stream = fdopen(c,"r");
            if ( !c_stream ) {
                close(c);
                continue;
            }

            /*
             * Initiate SSL for this client
             */
            sbio=BIO_new_socket(c,BIO_NOCLOSE);
            ssl=SSL_new(ctx);
            SSL_set_bio(ssl,sbio,sbio);

            if((r=SSL_accept(ssl)<=0))
                berr_exit("SSL accept error");

            g_array_insert_val(client,c,ssl);

            if ( c+1 > mx )
                mx = c + 1;

            /*
             * change FD_SET
             */

            FD_SET(c,&rx_set);
        }

        /*
         * check for client activity
         */
        for ( c=0; c<mx; ++c) {
            if ( c == sck_inet )
                continue;
            if ( FD_ISSET(c,&wk_set) ) {
                if (treat_user_request((SSL*)g_array_index (client , SSL*, c)) == EOF) {
                    SSL_shutdown((SSL*)g_array_index (client , SSL*, c));
                    FD_CLR(c,&rx_set);
                }
            }
        }

        for ( c = mx - 1;
            c >= 0 && !FD_ISSET(c,&rx_set);
            c = mx -1 )
            mx = c;
    }
    close(sck_inet);

    return NULL;
}



void user_check_and_decide (gpointer userdata, gpointer data){
    connection * conn_elt=NULL;

    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
        g_message("entering user_check\n");
    conn_elt = userpckt_decode((char *)userdata, 
        512);
    /* free userdata, packet is parsed now */
    g_free(userdata);
    /* if OK search and fill */
    if ( conn_elt != NULL ) {
        g_async_queue_push (connexions_queue,conn_elt);
    } else {
        if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_USER))
            g_message("User packet decoding failed\n");
    }
    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
        g_message("leaving user_check\n");
}

connection * userpckt_decode(char* dgram,int dgramsiz){
    long u_packet_id=0;
    char *pointer;
    connection* connexion;
    char passwd[128];
    char md5datas[512];
    char *usermd5datas;
    struct in_addr oneip;
    char onaip[16];
    char *result;
    u_int16_t firstf,lastf;
    struct crypt_data * crypt_internal_datas=g_private_get (crypt_priv);
    auth_field * packet_auth_field;
    /* decode dgram */
    switch (*dgram) {
      case 0x1:
        if (nuauth_protocol_version == 1){
            if ( *(dgram+1) == USER_REQUEST) {
                /* allocate connection */
                connexion = g_new0( connection,1);
                connexion->acl_groups=NULL;
                connexion->user_groups=NULL;
                if (connexion == NULL){
                    if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_USER)){
                        g_message("Can not allocate connexion\n");
                    }
                    return NULL;
                }

                /* parse packet */
                pointer=dgram+2;
                connexion->user_id=*(u_int16_t *)(pointer);
                pointer+=sizeof (u_int16_t);
                connexion->tracking_hdrs.saddr=(*(u_int32_t * )(pointer));
#if 0
                if ( connexion->tracking_hdrs.saddr != ntohl(addr_clnt) ){
                    g_warning("client addr (%lu) != source addr (%lu) !\n",connexion->tracking_hdrs.saddr, addr_clnt);
                    return NULL;
                } 
#endif
                pointer+=sizeof (u_int32_t);
                connexion->tracking_hdrs.daddr=(*(u_int32_t * )(pointer));
                pointer+=sizeof (u_int32_t);
                connexion->tracking_hdrs.protocol=*(u_int8_t *)(pointer);
                pointer+= sizeof (u_int8_t);
                /* PROV : swap FLAGS as no client use it ...*/
                pointer+=3 * sizeof (u_int8_t);
                switch (connexion->tracking_hdrs.protocol) {
                  case IPPROTO_TCP:
                    connexion->tracking_hdrs.source=(*(u_int16_t *)pointer);
                    pointer+=sizeof (u_int16_t);
                    connexion->tracking_hdrs.dest=(*(u_int16_t *)pointer);
                    pointer+=sizeof (u_int16_t);
                    connexion->tracking_hdrs.type=0;
                    connexion->tracking_hdrs.code=0;
                    break;
                  case IPPROTO_UDP:
                    connexion->tracking_hdrs.source=(*(u_int16_t *)pointer);
                    pointer+=sizeof (u_int16_t);
                    connexion->tracking_hdrs.dest=(*(u_int16_t *)pointer);
                    pointer+=sizeof (u_int16_t);
                    connexion->tracking_hdrs.type=0;
                    connexion->tracking_hdrs.code=0;
                    break;
                  case IPPROTO_ICMP:
                    connexion->tracking_hdrs.source=0;
                    connexion->tracking_hdrs.dest=0;
                    connexion->tracking_hdrs.type=*(u_int8_t *)(pointer);
                    pointer+=sizeof(u_int8_t);
                    connexion->tracking_hdrs.code=*(u_int8_t *)(pointer);
                    pointer+=3;
                    break;
                }
                /* get timestamp */
                connexion->timestamp=*(long *)(pointer);
                pointer+=sizeof(long);
                /* get random number */
                u_packet_id=*(long *)(pointer);
                pointer+=sizeof(long);
                /* get user md5datas */
                usermd5datas=strndup(pointer,34);

                if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
                    g_message("User "); 
                    print_connection(connexion,NULL);
                }

                /* get user datas : password, groups (filled in) */
                connexion->user_groups = (*module_user_check) (connexion->user_id,passwd);
                if (connexion->user_groups == NULL) {
                    if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
                        g_message("user_check return bad\n");
                    free_connection(connexion);
                    return NULL;
                }

                /*
                 * check MD5 crypt 
                 */

                /* construct md5datas */
                oneip.s_addr=htonl(connexion->tracking_hdrs.saddr);
                strncpy(onaip,inet_ntoa(oneip),16);
                oneip.s_addr=htonl(connexion->tracking_hdrs.daddr);

                if (connexion->tracking_hdrs.protocol != IPPROTO_ICMP) {
                    firstf=connexion->tracking_hdrs.source;
                    lastf=connexion->tracking_hdrs.dest;
                } else {
                    firstf=connexion->tracking_hdrs.type;
                    lastf=connexion->tracking_hdrs.code;
                }

                snprintf(md5datas,512,
                    "%s%u%s%u%ld%ld%s",
                    onaip,
                    firstf,
                    inet_ntoa(oneip),
                    lastf,
                    connexion->timestamp,
                    u_packet_id,
                    passwd);

                /* initialisation stuff */
                if (crypt_internal_datas == NULL){
                    crypt_internal_datas=g_new0(struct crypt_data,1);
                    g_private_set(crypt_priv,crypt_internal_datas);
                    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_USER))
                        g_message("Initiating crypt internal structure");
                }
                /* crypt datas */
                result = crypt_r(md5datas,usermd5datas,crypt_internal_datas);
                /* compare the two crypted datas */
                if ( strcmp (result, usermd5datas) != 0 ) {
                    /* bad sig dropping user packet ! */
                    if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_USER))
                        g_message("wrong md5 sig for packet %s \n",usermd5datas);
                    free(usermd5datas);
                    free_connection(connexion);
                    return NULL;
                } else {
                    free(usermd5datas);
                    /* 
                     * md5 done !
                     */

                    /* Is it a try to spoof MD5 ? */

                    /* set some default on connexion */
                    if (check_fill_user_counters(connexion->user_id,connexion->timestamp,u_packet_id,connexion->tracking_hdrs.saddr)){	
                        /* first reset timestamp to now */
                        connexion->timestamp=time(NULL);
                        connexion->state=STATE_USERPCKT;
                        /* acl part is NULL */
                        connexion->packet_id=NULL;
                        connexion->acl_groups=NULL;
                        return connexion;
                    } else {
                        if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
                            g_message("Bad user packet\n");
                        free_connection(connexion);
                        return NULL;
                    }
                }
            }
        } else {
            if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
                g_message("Bad version packet, protocol version 1\n");
            return NULL; 
        }
        /* Let's work on Protocol version 2 */
      case 0x2:

        if (nuauth_protocol_version == 2){
            if ( *(dgram+1) == USER_REQUEST) {
                u_int16_t total_len=0; 
                char * payload=dgram;
                /* allocate connection */
                connexion = g_new0( connection,1);

                /* parse packet */
                pointer=dgram+2;
                total_len=*(u_int16_t *)(pointer);
                if (total_len > dgramsiz){
                    /* big oops */
                    g_free(connexion);
                    return NULL;
                } 

                pointer+=sizeof (u_int16_t);
#if 0
                if ( connexion->tracking_hdrs.saddr != ntohl(addr_clnt) ){
                    g_warning("client addr (%lu) != source addr (%lu) !\n",connexion->tracking_hdrs.saddr, addr_clnt);
                    return NULL;
                } 
#endif

                /* iter on Field till we're inferior to total length */
                while (pointer - dgram < total_len){ 
                    int field_length=*(u_int16_t *)(pointer+2);
                    /* check if field length is coherent with respect to total length */
                    if (pointer - dgram + field_length <= total_len) {
                        /* get field_type field_flag */
                        u_int8_t field_type=*(u_int8_t *)(pointer);
                        u_int8_t field_flag=*(u_int8_t *)(pointer+1);
                        char * field_datas=pointer+4;
                        /* treat following field type */
                        switch (field_type) {
                          case PACKET_FIELD:
                            /* fill IP headers */
                            parse_packet_field(field_datas,field_flag,field_length,connexion);
                            break;
                          case USERNAME_FIELD:
                            /* we need to fill userid and password */
                            parse_username_field(field_datas,field_flag,field_length,connexion);
                            break;
                          case AUTHENTICATION_FIELD:
                            /* we get packet_id timestamp */
                            packet_auth_field = parse_authentication_field(field_datas,field_flag,field_length);
                            break;
                          default:
                            if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
                                g_message("Bad user packet, unknown field type\n");
                            free_connection(connexion);
                            return NULL;
                            break;
                        }
                    } else {
                        if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
                            g_message("Bad user packet, announced length is wrong\n");
                        free_connection(connexion);
                        return NULL;
                    }
                    pointer+=field_length;
                }
                /* check if paquet is complete */
                if ((connexion->timestamp)&&(connexion->username!=NULL)&&(packet_auth_field!=NULL)){
                    if (! get_user_datas(connexion,packet_auth_field))
                        return NULL;
                } else {
                    return NULL;
                }

                /* check authentication */
                if ( check_authentication(connexion,packet_auth_field)){
                    /* set some default on connexion */
                    if (check_fill_user_counters(connexion->user_id,connexion->timestamp,u_packet_id,connexion->tracking_hdrs.saddr)){	
                        /* first reset timestamp to now */
                        connexion->timestamp=time(NULL);
                        connexion->state=STATE_USERPCKT;
                        /* acl part is NULL */
                        connexion->packet_id=NULL;
                        connexion->acl_groups=NULL;
                        free_auth_field(packet_auth_field);
                        return connexion;
                    } else {
                        if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
                            g_message("Bad user packet\n");
                        free_connection(connexion);
                        return NULL;
                    }
                } else {
                    free_connection(connexion);
                    free_auth_field(packet_auth_field);
                    return NULL;
                }
            }
        } else {
            if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
                g_message("Bad version packet, protocol version 1\n");
            return NULL; 
        }
    }
    /* FIXME : free dgram see over */
    return NULL;
}


/* parse packet field */
void * parse_packet_field(char* pointer, u_int8_t flag ,connection * connexion,int length){

    connexion->tracking_hdrs.saddr=(*(u_int32_t * )(pointer));
    pointer+=sizeof (u_int32_t);
    connexion->tracking_hdrs.daddr=(*(u_int32_t * )(pointer));
    pointer+=sizeof (u_int32_t);
    connexion->tracking_hdrs.protocol=*(u_int8_t *)(pointer);
    pointer+= sizeof (u_int8_t);
    /* PROV : swap FLAGS as no client use it ...*/
    pointer+=3 * sizeof (u_int8_t);
    switch (connexion->tracking_hdrs.protocol) {
      case IPPROTO_TCP:
        connexion->tracking_hdrs.source=(*(u_int16_t *)pointer);
        pointer+=sizeof (u_int16_t);
        connexion->tracking_hdrs.dest=(*(u_int16_t *)pointer);
        pointer+=sizeof (u_int16_t);
        connexion->tracking_hdrs.type=0;
        connexion->tracking_hdrs.code=0;
        break;
      case IPPROTO_UDP:
        connexion->tracking_hdrs.source=(*(u_int16_t *)pointer);
        pointer+=sizeof (u_int16_t);
        connexion->tracking_hdrs.dest=(*(u_int16_t *)pointer);
        pointer+=sizeof (u_int16_t);
        connexion->tracking_hdrs.type=0;
        connexion->tracking_hdrs.code=0;
        break;
      case IPPROTO_ICMP:
        connexion->tracking_hdrs.source=0;
        connexion->tracking_hdrs.dest=0;
        connexion->tracking_hdrs.type=*(u_int8_t *)(pointer);
        pointer+=sizeof(u_int8_t);
        connexion->tracking_hdrs.code=*(u_int8_t *)(pointer);
        pointer+=3;
        break;
    }
    return NULL;
}

/* parse username field */
void * parse_username_field(char * dgram, u_int8_t flag, int length ,connection * connexion){ 
    connexion->username = g_strndup(dgram,length);
    return NULL;


}

int get_user_datas(connection *connexion,auth_field* packet_auth_field){
    /* check if user is in the cache */
    
    /* get user datas : groups (filled in), auth_field (password if md5) */
    connexion->user_groups = (*module_user_check_v2) (connexion,packet_auth_field);
    if (connexion->user_groups == NULL) {
        if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
            g_message("user_check return bad\n");
        free_connection(connexion);
        return 0;
    }
    return -1;
}



/* parse authentication field */

auth_field * parse_authentication_field(char * dgram,  u_int8_t flag ,int length){ 
    auth_field * packet_auth_field=NULL;
    switch (flag) {
      case MD5_AUTH:
        packet_auth_field=g_new0(auth_field,1);
        packet_auth_field->type=MD5_AUTH;
        packet_auth_field->md5_datas=g_new0(md5_auth_field,1);
        (packet_auth_field->md5_datas)->u_packet_id=*(long*)dgram;
        dgram+=sizeof(long);
        g_strlcpy((packet_auth_field->md5_datas)->md5sum,dgram,34);
        return packet_auth_field;
      default:
        if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
            g_message("Unknown authentication type");
        return NULL;
    }
    return packet_auth_field;
}


int check_authentication(connection * connexion,auth_field * packet_auth_field ){
    switch (packet_auth_field->type) {
      case  MD5_AUTH:
        return check_md5_sig(connexion,packet_auth_field->md5_datas); 
      default:
        if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
            g_message("Unknown authentication type");
        return 0;
        break;
    }
}

/* check md5 sig */
int check_md5_sig(connection * connexion,md5_auth_field * authdatas ){
    struct in_addr oneip;
    char onaip[16];
    char md5datas[512];
    char *result;
    u_int16_t firstf,lastf;
    struct crypt_data * crypt_internal_datas=g_private_get (crypt_priv);
    /* construct md5datas */
    oneip.s_addr=htonl(connexion->tracking_hdrs.saddr);
    strncpy(onaip,inet_ntoa(oneip),16);
    oneip.s_addr=htonl(connexion->tracking_hdrs.daddr);

    if (connexion->tracking_hdrs.protocol != IPPROTO_ICMP) {
        firstf=connexion->tracking_hdrs.source;
        lastf=connexion->tracking_hdrs.dest;
    } else {
        firstf=connexion->tracking_hdrs.type;
        lastf=connexion->tracking_hdrs.code;
    }

    snprintf(md5datas,512,
        "%s%u%s%u%ld%ld%s",
        onaip,
        firstf,
        inet_ntoa(oneip),
        lastf,
        connexion->timestamp,
        authdatas->u_packet_id,
        authdatas->password);

    /* initialisation stuff */
    if (crypt_internal_datas == NULL){
        crypt_internal_datas=g_new0(struct crypt_data,1);
        g_private_set(crypt_priv,crypt_internal_datas);
        if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_USER))
            g_message("Initiating crypt internal structure");
    }
    /* crypt datas */
    result = crypt_r(md5datas,authdatas->md5sum,crypt_internal_datas);
    /* compare the two crypted datas */
    if ( strcmp (result, authdatas->md5sum) != 0 ) {
        /* bad sig dropping user packet ! */
        if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_USER))
            g_message("wrong md5 sig for packet %s \n",authdatas->md5sum);
        return 0; 
    } else {
        return 1;
    }
}

void free_auth_field(auth_field * field){
    switch (field->type){
      case MD5_AUTH:
        if (field->md5_datas)
            g_free(field->md5_datas);
        if ((field->md5_datas)->password)
            g_free(field->password);
        g_free(field);
    }	
}


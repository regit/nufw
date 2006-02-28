/*
 ** Copyright(C) 2004,2005 INL
 ** written by  Eric Leblond <regit@inl.fr>
 **             Vincent Deffontaines <gryzor@inl.fr>
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
 **
 */

#include "auth_srv.h"

struct tls_nufw_context_t {
    int mx;
    int sck_inet;
    struct sockaddr_in addr_inet;
    fd_set tls_rx_set; /* read set */
};

/** 
 * get RX paquet from a TLS client connection and send it to user authentication threads.
 *
 * - Argument : SSL RX packet
 * - Return : 1 if read done, EOF if read complete
 */
static int treat_nufw_request (nufw_session_t *c_session)
{
    unsigned char *dgram=NULL;
    int dgram_size;

    if (c_session == NULL)
        return 1;
    
    /* copy packet datas */
    dgram = g_new0(unsigned char, BUFSIZE);
    dgram_size = gnutls_record_recv(*(c_session->tls), dgram, BUFSIZE) ;
    if (  dgram_size > 0 ){
        connection_t *current_conn = authpckt_decode(dgram , dgram_size);
        if (current_conn != NULL){
            current_conn->socket=0;
            current_conn->tls=c_session;
            /* gonna feed the birds */

            if (current_conn->state == AUTH_STATE_HELLOMODE){
                struct internal_message *message = g_new0(struct internal_message,1);
                message->type=INSERT_MESSAGE;
                message->datas=current_conn;
                current_conn->state = AUTH_STATE_AUTHREQ;
                g_async_queue_push (nuauthdatas->localid_auth_queue,message);
            } else {
                current_conn->state = AUTH_STATE_AUTHREQ;
                g_async_queue_push (nuauthdatas->connections_queue,
                        current_conn);
            }
        } else {
            if ( dgram[1] != AUTH_CONTROL && dgram[1] != AUTH_CONN_DESTROY  )
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_PACKET)){
                    g_warning("Can't parse packet, this IS bad !\n");
                }
        }
    } else {
        g_free(dgram);
        g_atomic_int_dec_and_test(&(c_session->usage));
        return EOF;
    }
    g_free(dgram);
    return 1;
}

void close_nufw_servers(int signal) 
{
    g_mutex_lock(nufw_servers_mutex);
    g_hash_table_destroy(nufw_servers);
    nufw_servers=NULL;
    g_mutex_unlock(nufw_servers_mutex);
}

void clean_nufw_session(nufw_session_t * c_session) 
{
    gnutls_transport_ptr socket_tls;
    socket_tls=gnutls_transport_get_ptr(*(c_session->tls));
    close((int)socket_tls);
#ifdef DEBUG_ENABLE
    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
        g_message("close nufw session calling");
#endif
    if (c_session->tls ){
        gnutls_bye(
                *(c_session->tls)	
                , GNUTLS_SHUT_RDWR);
        gnutls_deinit(
                *(c_session->tls)	
                );
        g_free(c_session->tls);
    } else {


#ifdef DEBUG_ENABLE
        if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
            g_warning("close nufw session was called but NULL");
#endif

    }

#ifdef DEBUG_ENABLE
    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
        g_message("close nufw session calling");
#endif
}

/**
 * \return If an error occurs returns 1, else returns 0.
 */
int tls_nufw_accept(struct tls_nufw_context_t *context) 
{
    int conn_fd;
    struct sockaddr_in addr_clnt;
    unsigned int len_inet;
    nufw_session_t *nu_session;

    /*
     * Wait for a connect
     */
    len_inet = sizeof addr_clnt;
    conn_fd = accept (context->sck_inet,
            (struct sockaddr *)&addr_clnt,
            &len_inet);
    if (conn_fd == -1){
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
            g_warning("accept");
        }
    }

    /* test if server is in the list of authorized servers */
    if (! check_inaddr_in_array(addr_clnt.sin_addr,nuauthconf->authorized_servers)){
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
            g_warning("unwanted server (%s)\n",inet_ntoa(addr_clnt.sin_addr));
        }
        close(conn_fd);
        return 1;
    }
#if 0
    if ( conn_fd >= nuauth_tls_max_servers) {
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
            g_warning("too much servers (%d configured)\n",nuauth_tls_max_servers);
        }
        close(conn_fd);
        continue;
    }
#endif

    /* initialize TLS */
    nu_session = g_new0(nufw_session_t, 1);
    nu_session->usage=0;
    nu_session->alive=TRUE;
    nu_session->peername.s_addr=addr_clnt.sin_addr.s_addr;
    if (tls_connect(conn_fd,&(nu_session->tls)) == SASL_OK){
        g_mutex_lock(nufw_servers_mutex);
        g_hash_table_insert(nufw_servers,GINT_TO_POINTER(conn_fd),nu_session);
        g_mutex_unlock(nufw_servers_mutex);
        FD_SET(conn_fd,&context->tls_rx_set);
        if ( conn_fd+1 > context->mx )
            context->mx = conn_fd + 1;
    } else {
        g_free(nu_session);
    }
    return 0;
}    

void tls_nufw_main_loop(struct tls_nufw_context_t *context) 
{
    int n,c,z;
    fd_set wk_set; /* working set */
    struct timeval tv;

    for(;;){
        /* copy rx set to working set */
        FD_ZERO(&wk_set);
        for (z=0;z<context->mx;++z){
            if (FD_ISSET(z,&context->tls_rx_set))
                FD_SET(z,&wk_set);
        }

        /* define timeout */
        tv.tv_sec=2;
        tv.tv_usec=30000;
        
        n=select(context->mx,&wk_set,NULL,NULL,&tv);
        if (n == -1) {
            g_warning("select() failed, exiting\n");
            exit(EXIT_FAILURE);
        } else if (!n) {
            continue;
        }

        /*
         * Check if a connect has occured
         */

        if (FD_ISSET(context->sck_inet,&wk_set) ){
            if (tls_nufw_accept(context))
                continue;
        }

        /*
         * check for server activity
         */
        for ( c=0; c<context->mx; ++c) {
            if ( c == context->sck_inet )
                continue;
            if ( FD_ISSET(c,&wk_set) ) {
                nufw_session_t * c_session;
#ifdef DEBUG_ENABLE
                if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
                    g_message("activity on %d\n",c);
#endif
                c_session=g_hash_table_lookup( nufw_servers , GINT_TO_POINTER(c));
                g_atomic_int_inc(&(c_session->usage));
                if (treat_nufw_request(c_session) == EOF) {
                    /* get session link with c */
#ifdef DEBUG_ENABLE
                    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_USER))
                        g_message("nufw server disconnect on %d\n",c);
#endif
                    FD_CLR(c,&context->tls_rx_set);
                    g_mutex_lock(nufw_servers_mutex);
                    if (g_atomic_int_get(&(c_session->usage)) == 0) {
                        /* clean client structure */
                        g_hash_table_remove(nufw_servers,GINT_TO_POINTER(c));
                    } else {
                        g_hash_table_steal(nufw_servers,GINT_TO_POINTER(c));
                        c_session->alive=FALSE;
                    }
                    g_mutex_unlock(nufw_servers_mutex);
                    close(c);
                }
            }
        }

        for ( c = context->mx - 1;
                c >= 0 && !FD_ISSET(c,&context->tls_rx_set);
                c = context->mx -1 ){
            context->mx = c;
        }
    }
    close(context->sck_inet);
}    

void tls_nufw_init(struct tls_nufw_context_t *context)
{    
    int z;
    gint option_value;
#if 0
    struct sigaction action;

    char *configfile=DEFAULT_CONF_FILE;
    gpointer vpointer;
    confparams nuauth_tls_vars[] = {
        { "nuauth_tls_max_servers" , G_TOKEN_INT ,NUAUTH_TLS_MAX_SERVERS, NULL }
    };
    int nuauth_tls_max_servers=NUAUTH_TLS_MAX_SERVERS;
    /* get config file setup */
    /* parse conf file */
    parse_conffile(configfile,sizeof(nuauth_tls_vars)/sizeof(confparams),nuauth_tls_vars);
    /* set variable value from config file */
    vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_max_servers");
    nuauth_tls_max_servers=*(int*)(vpointer?vpointer:&nuauth_tls_max_servers);
#endif

    /* build servers hash */
    nufw_servers = g_hash_table_new_full(
            NULL,
            NULL,
            NULL,
            (GDestroyNotify)clean_nufw_session
            );
    nufw_servers_mutex = g_mutex_new();

    /* this must be called once in the program */
#if 0
    /* intercept SIGTERM */
    action.sa_handler = tls_nuauth_cleanup;
    sigemptyset( & (action.sa_mask));
    action.sa_flags = 0;
    if ( sigaction( SIGTERM, & action , NULL ) != 0) {
        printf("Error\n");
        exit(EXIT_FAILURE);
    }
#endif

    /* open the socket */
    context->sck_inet = socket (AF_INET, SOCK_STREAM, 0);
    if (context->sck_inet == -1)
    {
        g_warning("socket() failed, exiting");
        exit(-1);
    }

    option_value=1;
    setsockopt (context->sck_inet, SOL_SOCKET, SO_REUSEADDR, 
            &option_value,	sizeof(option_value));

    memset(&context->addr_inet,0,sizeof context->addr_inet);
    context->addr_inet.sin_family= AF_INET;
    context->addr_inet.sin_port=htons(nuauthconf->authreq_port);
    context->addr_inet.sin_addr.s_addr=nuauthconf->nufw_srv->s_addr;
    z = bind (context->sck_inet,
            (struct sockaddr *)&context->addr_inet,
            sizeof context->addr_inet);
    if (z == -1)
    {
        g_warning ("nufw bind() failed to %s:%d, exiting",inet_ntoa(context->addr_inet.sin_addr),nuauthconf->authreq_port);
        exit(-1);
    }

    /* Listen ! */
    z = listen(context->sck_inet,20);
    if (z == -1)
    {
        g_warning ("nufw listen() failed, exiting");
        exit(-1);
    }

    /* init fd_set */
    context->mx=context->sck_inet+1;
    mx_nufw_queue=g_async_queue_new ();

    FD_ZERO(&context->tls_rx_set);
    FD_SET(context->sck_inet,&context->tls_rx_set);
}

/**
 * TLS nufw packet server running in a thread.
 *
 * \return NULL
 */
void* tls_nufw_authsrv()
{
    struct tls_nufw_context_t context;

    tls_nufw_init(&context);

    tls_nufw_main_loop(&context);

    return NULL;
}


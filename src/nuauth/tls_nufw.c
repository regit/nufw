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

/** \file tls_nufw.c
 *  \brief Manage NuFW firewall connections and messages.
 *   
 * The main thread is tls_nufw_authsrv() which call tls_nufw_main_loop().
 */

struct tls_nufw_context_t {
    int mx;
    int sck_inet;
    fd_set tls_rx_set; /* read set */
};

/** 
 * Get RX paquet from a TLS client connection and send it to user
 * authentication threads:
 *   - nuauthdatas->localid_auth_queue (see ::localid_auth()), if connection
 *     state is #AUTH_STATE_HELLOMODE
 *   - nuauthdatas->connections_queue (see search_and_fill()), otherwise
 *
 * \param c_session SSL RX packet
 * \return Returns 1 if read is done, EOF if read is completed
 */
static int treat_nufw_request (nufw_session_t *c_session)
{
    unsigned char dgram[CLASSIC_NUFW_PACKET_SIZE];
    int dgram_size;

    if (c_session == NULL)
        return NU_EXIT_OK;
    
    /* copy packet datas */
    g_mutex_lock(c_session->tls_lock);
    dgram_size = gnutls_record_recv(*(c_session->tls), dgram, CLASSIC_NUFW_PACKET_SIZE) ;
    g_mutex_unlock(c_session->tls_lock);
    if (  dgram_size > 0 ){
        connection_t *current_conn;
        int ret = authpckt_decode(dgram , (unsigned int)dgram_size, &current_conn);
        switch (ret){
            case NU_EXIT_ERROR:
                g_atomic_int_dec_and_test(&(c_session->usage));
                return NU_EXIT_ERROR;
            case NU_EXIT_OK:
                if (current_conn != NULL){
                    current_conn->socket=0;
                    current_conn->tls=c_session;

                    /* gonna feed the birds */
                    if (current_conn->state == AUTH_STATE_HELLOMODE){
                        debug_log_message(DEBUG, AREA_GW,
                                "(*) NuFW auth request (hello mode): packetid=%u",
                                (uint32_t)GPOINTER_TO_UINT(current_conn->packet_id->data));
                        struct internal_message *message = g_new0(struct internal_message,1);
                        message->type=INSERT_MESSAGE;
                        message->datas=current_conn;
                        current_conn->state = AUTH_STATE_AUTHREQ;
                        g_async_queue_push (nuauthdatas->localid_auth_queue,message);
                    } else {
                        debug_log_message(DEBUG, AREA_GW,
                                "(*) NuFW auth request (hello mode): packetid=%u",
                                (uint32_t)GPOINTER_TO_UINT(current_conn->packet_id->data));
                        g_async_queue_push (nuauthdatas->connections_queue, current_conn);
                    }
                } 
                return NU_EXIT_OK;
            case NU_EXIT_NO_RETURN:
                g_atomic_int_dec_and_test(&(c_session->usage));
        }
    } else {
        g_message("nufw failure at %s:%d",__FILE__,__LINE__);
        g_atomic_int_dec_and_test(&(c_session->usage));
        return NU_EXIT_ERROR;
    }
    return NU_EXIT_OK;
}

/**
 * Close the TLS NuFW servers
 */
void close_nufw_servers() 
{
    g_mutex_lock(nufw_servers_mutex);
    g_hash_table_destroy(nufw_servers);
    nufw_servers=NULL;
    g_mutex_unlock(nufw_servers_mutex);
}

/**
 * Clean a NuFW TLS session: send "bye", deinit the connection
 * and free the memory.
 */
void clean_nufw_session(nufw_session_t * c_session) 
{
    gnutls_transport_ptr socket_tls;
    socket_tls=gnutls_transport_get_ptr(*(c_session->tls));
    close((int)socket_tls);
    debug_log_message(VERBOSE_DEBUG, AREA_GW, "close nufw session calling");
    if (c_session->tls ){
        gnutls_bye(
                *(c_session->tls)	
                , GNUTLS_SHUT_RDWR);
        gnutls_deinit(
                *(c_session->tls)	
                );
        g_free(c_session->tls);
    } else {


        debug_log_message(VERBOSE_DEBUG, AREA_GW, "close nufw session was called but NULL");

    }
    g_mutex_free(c_session->tls_lock);

    debug_log_message(VERBOSE_DEBUG, AREA_GW, "close nufw session: done");
}

/**
 * Function called on new NuFW connection: create a new TLS session using
 * tls_connect().
 * 
 * \return If an error occurs returns 1, else returns 0.
 */
int tls_nufw_accept(struct tls_nufw_context_t *context) 
{
    int conn_fd;
    struct sockaddr_storage sockaddr;
    struct sockaddr_in *sockaddr4 = (struct sockaddr_in *)&sockaddr;
    struct sockaddr_in6 *sockaddr6 = (struct sockaddr_in6 *)&sockaddr;
    struct in6_addr addr;
    char addr_ascii[INET6_ADDRSTRLEN];
    unsigned int len_inet;
    nufw_session_t *nu_session;

    /* Accept the connection */
    len_inet = sizeof sockaddr;
    conn_fd = accept (context->sck_inet,
            (struct sockaddr *)&sockaddr,
            &len_inet);
    if (conn_fd == -1){
        log_message(WARNING, AREA_MAIN, "accept");
    }
   
    /* Extract client address (convert it to IPv6 if it's IPv4) */
    if (sockaddr6->sin6_family == AF_INET) {
        addr.s6_addr32[0] = 0;
        addr.s6_addr32[1] = 0;
        addr.s6_addr32[2] = 0xffff0000;
        addr.s6_addr32[3] = sockaddr4->sin_addr.s_addr;
    } else {
        addr = sockaddr6->sin6_addr;
    }

    /* test if server is in the list of authorized servers */
    if (!check_inaddr_in_array(&addr, nuauthconf->authorized_servers)){
        if (inet_ntop(AF_INET6, &addr, addr_ascii, sizeof(addr_ascii)) != NULL)
            log_message(WARNING, AREA_MAIN, "unwanted nufw server (%s)", addr_ascii);
        close(conn_fd);
        return 1;
    }
#if 0
    if ( conn_fd >= nuauth_tls_max_servers) {
        log_message(WARNING, AREA_MAIN, "too much servers (%d configured)\n",nuauth_tls_max_servers);
        close(conn_fd);
        continue;
    }
#endif

    /* initialize TLS */
    nu_session = g_new0(nufw_session_t, 1);
    nu_session->usage=0;
    nu_session->alive=TRUE;
    nu_session->peername = addr;
    if (tls_connect(conn_fd,&(nu_session->tls)) == SASL_OK){
	nu_session->tls_lock = g_mutex_new();
        g_mutex_lock(nufw_servers_mutex);
        g_hash_table_insert(nufw_servers,GINT_TO_POINTER(conn_fd),nu_session);
        g_mutex_unlock(nufw_servers_mutex);
        FD_SET(conn_fd,&context->tls_rx_set);
        if ( conn_fd+1 > context->mx )
            context->mx = conn_fd + 1;
        g_message("[+] NuFW: new client connected on socket %d",conn_fd);
    } else {
        g_free(nu_session);
    }
    return 0;
}    

/**
 * NuFW TLS thread main loop:
 *   - Wait events (message/new connection) using select() with a timeout
 *     of one second
 *   - Accept new connections: call tls_nufw_accept()
 *   - Read and process new packets using treat_nufw_request()
 */
void tls_nufw_main_loop(struct tls_nufw_context_t *context, GMutex *mutex) 
{
    int n,c,z;
    fd_set wk_set; /* working set */
    struct timeval tv;

    log_message(INFO, AREA_MAIN, "[+] NuAuth is waiting for NuFW connections.");
    while (g_mutex_trylock(mutex))
    {
        g_mutex_unlock(mutex);

        /* copy rx set to working set */
        FD_ZERO(&wk_set);
        for (z=0;z<context->mx;++z){
            if (FD_ISSET(z,&context->tls_rx_set))
                FD_SET(z,&wk_set);
        }

        /* wait new events during 1 second */
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        n = select(context->mx,&wk_set,NULL,NULL,&tv);
        if (n == -1) {
            /* Signal was catched: just ignore it */
            if (errno == EINTR)
            {
                log_message(CRITICAL, AREA_MAIN,
                        "Warning: tls nufw select() failed: signal was catched.");
                continue;
            }

            switch(errno)
            {
                case EBADF:
                    g_message("Bad file descriptor in one of the set.");
                    break;
                case EINVAL:
                    g_message("Negative value for socket");
                    break;
                case ENOMEM:
                    g_message("Not enough memory");
                    break;
            }
            g_warning("select() failed, exiting at %s:%d in %s (errno=%i)\n",
                    __FILE__,__LINE__,__func__,errno);
            exit(EXIT_FAILURE);
        } else if (!n) {
            continue;
        }

        /* Check if a connect has occured */
        if (FD_ISSET(context->sck_inet,&wk_set) ){
            if (tls_nufw_accept(context)){
                continue;
            }
        }

        /* check for server activity */
        for ( c=0; c<context->mx; ++c)
        {
            if ( c == context->sck_inet )
                continue;

            if ( FD_ISSET(c,&wk_set) ) {
                nufw_session_t * c_session;
                debug_log_message(VERBOSE_DEBUG, AREA_GW, "nufw activity on socket %d",c);
                c_session=g_hash_table_lookup( nufw_servers , GINT_TO_POINTER(c));
                g_atomic_int_inc(&(c_session->usage));
                if (treat_nufw_request(c_session) == NU_EXIT_ERROR) {
                    /* get session link with c */
                    debug_log_message(DEBUG, AREA_GW, "nufw server disconnect on %d",c);
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

/**
 * Initialize the NuFW TLS servers thread
 */
void tls_nufw_init(struct tls_nufw_context_t *context)
{    
    int socket_fd;
    gint option_value;
    struct addrinfo *res;
    struct addrinfo hints;
    int ecode;

    memset(&hints, 0, sizeof hints);
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = PF_UNSPEC;
    ecode = getaddrinfo(NULL, nuauthconf->authreq_port, &hints, &res);
    if (ecode != 0)
    {
	g_error("Fail to init. user server address: %s\n", gai_strerror(ecode));
	exit(EXIT_SUCCESS);
    }

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
    context->sck_inet = socket (res->ai_family, res->ai_socktype, res->ai_protocol);
    if (context->sck_inet == -1)
    {
        g_warning("socket() failed, exiting");
        exit(EXIT_FAILURE);
    }

    option_value=1;
    setsockopt (context->sck_inet, SOL_SOCKET, SO_REUSEADDR, 
            &option_value,	sizeof(option_value));

    socket_fd = bind (context->sck_inet, res->ai_addr, res->ai_addrlen);
    if (socket_fd < 0)
    {
        g_warning ("nufw bind() failed on port %s, exiting", nuauthconf->authreq_port);
        exit(EXIT_FAILURE);
    }

    /* Listen ! */
    socket_fd = listen(context->sck_inet,20);
    if (socket_fd == -1)
    {
        g_warning ("nufw listen() failed, exiting");
        exit(EXIT_FAILURE);
    }

    /* init fd_set */
    context->mx=context->sck_inet+1;

    FD_ZERO(&context->tls_rx_set);
    FD_SET(context->sck_inet,&context->tls_rx_set);
}

/**
 * TLS nufw packet server thread: call tls_nufw_init() and then live
 * in tls_nufw_main_loop().
 *
 * \return NULL
 */
void* tls_nufw_authsrv(GMutex *mutex)
{
    struct tls_nufw_context_t context;
    tls_nufw_init(&context);
    tls_nufw_main_loop(&context, mutex);
    return NULL;
}


/*
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

/* This must be included before anything else */
#if HAVE_CONFIG_H
#  include <config.h>
#endif


#include <opflex/logging/internal/logging.hpp>
#include <opflex/yajr/internal/comms.hpp>

/*
                             _        _   _
                            / \   ___| |_(_)_   _____
                           / _ \ / __| __| \ \ / / _ \
                          / ___ \ (__| |_| |\ V /  __/
                         /_/   \_\___|\__|_| \_/ \___|

              ____                            _   _
             / ___|___  _ __  _ __   ___  ___| |_(_) ___  _ __  ___
            | |   / _ \| '_ \| '_ \ / _ \/ __| __| |/ _ \| '_ \/ __|
            | |__| (_) | | | | | | |  __/ (__| |_| | (_) | | | \__ \
             \____\___/|_| |_|_| |_|\___|\___|\__|_|\___/|_| |_|___/

                                                            (Active Connections)
*/

/*
   ____        _     _ _        _       _             __
  |  _ \ _   _| |__ | (_) ___  (_)_ __ | |_ ___ _ __ / _| __ _  ___ ___  ___
  | |_) | | | | '_ \| | |/ __| | | '_ \| __/ _ \ '__| |_ / _` |/ __/ _ \/ __|
  |  __/| |_| | |_) | | | (__  | | | | | ||  __/ |  |  _| (_| | (_|  __/\__ \
  |_|    \__,_|_.__/|_|_|\___| |_|_| |_|\__\___|_|  |_|  \__,_|\___\___||___/

                                                             (Public interfaces)
*/

::yajr::Peer * ::yajr::Peer::create(
        std::string const & host,
        std::string const & service,
        ::yajr::Peer::StateChangeCb connectionHandler,
        void * data,
        UvLoopSelector uvLoopSelector,
        bool nullTermination_
    ) {

    LOG(INFO) << host << ":" << service;

    ::yajr::comms::internal::ActiveTcpPeer * peer = NULL;
#if __cpp_exceptions || __EXCEPTIONS
    try {
#endif
        peer = new ::yajr::comms::internal::ActiveTcpPeer(
                host,
                service,
                connectionHandler,
                data,
                uvLoopSelector);
#if __cpp_exceptions || __EXCEPTIONS
    } catch(const std::bad_alloc&) {
    }
#endif

    if (!peer) {
        LOG(WARNING) << ": out of memory, dropping new peer on the floor";
        return NULL;
    }

    peer->nullTermination = nullTermination_;
    peer->insert(::yajr::comms::internal::Peer::LoopData::TO_RESOLVE);
    return peer;
}

::yajr::Peer * ::yajr::Peer::create(
        std::string const & socketName,
        ::yajr::Peer::StateChangeCb connectionHandler,
        void * data,
        UvLoopSelector uvLoopSelector,
        bool nullTermination_
   ) {

    ::yajr::comms::internal::ActiveUnixPeer * peer = NULL;
#if __cpp_exceptions || __EXCEPTIONS
    try {
#endif
        peer = new ::yajr::comms::internal::ActiveUnixPeer(
                    socketName,
                    connectionHandler,
                    data,
                    uvLoopSelector);
#if __cpp_exceptions || __EXCEPTIONS
    } catch(const std::bad_alloc&) {
    }
#endif

    if (!peer) {
        LOG(WARNING) << ": out of memory, dropping new peer on the floor";
        return NULL;
    }
    peer->nullTermination = nullTermination_;
    peer->insert(::yajr::comms::internal::Peer::LoopData::TO_RESOLVE);
    return peer;
}


namespace yajr {
    namespace comms {

using namespace yajr::comms::internal;

namespace internal {
/*
                     ____      _ _ _                _
                    / ___|__ _| | | |__   __ _  ___| | _____
                   | |   / _` | | | '_ \ / _` |/ __| |/ / __|
                   | |__| (_| | | | |_) | (_| | (__|   <\__ \
                    \____\__,_|_|_|_.__/ \__,_|\___|_|\_\___/

                                                                     (Callbacks)
*/
void retry_later(ActivePeer * peer) {

    if (peer->destroying_) {
        LOG(INFO) << peer << " peer is being destroyed. not inserting in RETRY_TO_CONNECT";
        return;
    }

    peer->unlink();
    peer->insert(internal::Peer::LoopData::RETRY_TO_CONNECT);

    assert(peer->uvRefCnt_ > 0);
}

void on_active_connection(uv_connect_t *req, int status) {

    ActivePeer * peer = Peer::get(req);  // can't possibly crash yet

    if (status == UV_ECANCELED) {

        /* the peer might have been deleted, so we have to avoid accessing any
         * of its members */
        LOG(DEBUG) << peer << " has had a connection attempt cancelled";
        peer->onError(status);
        return;
    }

    if (peer->destroying_) {
        peer->down();
        return;
    }

    if (status < 0) {
        LOG(WARNING) << "connect: [" << uv_err_name(status) << "] " << uv_strerror(status);
        peer->onFailedConnect(status);
        return;
    }

    if (peer->unchoke()) {
        retry_later(peer);
        return;
    }

    peer->unlink();
    peer->insert(internal::Peer::LoopData::ONLINE);

    /* kick the ball */
    peer->onConnect();

}

void on_resolved(uv_getaddrinfo_t * req, int status, struct addrinfo *resp) {

    ActiveTcpPeer * peer = Peer::get(req);
    assert(!peer->passive_);

    if (peer->destroying_) {
        LOG(INFO) << peer << " peer is being destroyed. down() it";
        peer->down();
        return;
    }

    if (status < 0) {
        LOG(WARNING) << "getaddrinfo callback error: [" << uv_err_name(status)
            << "] " << uv_strerror(status);
        peer->status_ = Peer::kPS_FAILED_TO_RESOLVE;
        uv_freeaddrinfo(resp);

        peer->down();
        return retry_later(peer);
    }

    peer->status_ = Peer::kPS_RESOLVED;

    int rc;
    if ((rc = peer->tcpInit())) {

        peer->down();
        return retry_later(peer);

    }

    peer->_.ai_next = peer->_.ai = resp;
    if ((rc = connect_to_next_address(peer))) {
        LOG(WARNING) << "connect_to_next_address: [" << uv_err_name(rc) << "] "
            << uv_strerror(rc);
        if (!uv_is_closing(peer->getHandle())) {
            uv_close(peer->getHandle(), on_close);
        }
        return retry_later(peer);
    }

    peer->status_ = Peer::kPS_CONNECTING;
}


/*
     _   _ _   _ _ _ _            __                  _   _
    | | | | |_(_) (_) |_ _   _   / _|_   _ _ __   ___| |_(_) ___  _ __  ___
    | | | | __| | | | __| | | | | |_| | | | '_ \ / __| __| |/ _ \| '_ \/ __|
    | |_| | |_| | | | |_| |_| | |  _| |_| | | | | (__| |_| | (_) | | | \__ \
     \___/ \__|_|_|_|\__|\__, | |_|  \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
                         |___/
                                                             (Utility functions)
*/

void debug_address(struct addrinfo const * ai, size_t m = 0) {

    if (!LOG_SHOULD_EMIT(TRACE)) {
        return;
    }

    /* most importantly! */
    if (!ai) {
        return;
    }

    char host[48] = "<n/a>";
    char service[6] = "<n/a>";

    static char const * msg[2][2] = {
        {
            "Attempting connect to host ",
            " on port ",
        },
        {
            "Resolved to ip ",
            " and port ",
        },
    };

    /* this won't block, thanks to the flags */
    (void) getnameinfo(ai->ai_addr,
                       ai->ai_addrlen,
                       host,
                       sizeof(host),
                       service,
                       sizeof(service),
                       NI_NUMERICHOST | NI_NUMERICSERV
                      );

    LOG(TRACE)
        << msg[m][0]
        <<           host
        << msg[m][1]
        <<           service
        <<   " ai_flags="
        << ai->ai_flags
        <<   " ai_family="
        << ai->ai_family
        <<   " ai_socktype="
        << ai->ai_socktype
        <<   " ai_protocol="
        << ai->ai_protocol
        <<   " ai_addrlen="
        << ai->ai_addrlen
        <<    " ai_canonname="
        << (ai->ai_canonname ?: "")
    ;
}

void swap_stack_on_close(uv_handle_t * h) {
    ActiveTcpPeer * peer = Peer::get<ActiveTcpPeer>(h);  // can't possibly crash yet

    int rc;
    if ((rc = peer->tcpInit())) {

        peer->down();
        retry_later(peer);

        return;
    }

    if ((rc = connect_to_next_address(peer, false))) {
        LOG(WARNING)
            << "connect_to_next_address: ["
            << uv_err_name(rc)
            << "] "
            << uv_strerror(rc);
        if (!uv_is_closing(peer->getHandle())) {
            uv_close(peer->getHandle(), on_close);
        }
        return retry_later(peer);
    }
}

int connect_to_next_address(ActiveTcpPeer * peer, bool swap_stack) {
    struct addrinfo const * ai = peer->_.ai_next;
    debug_address(ai);

    /* BAIL if destroying */
    if (peer->destroying_) {

        LOG(INFO) << peer << " peer is being destroyed. down() it";
        peer->down();
        return UV_ECANCELED;
    }

    int rc = UV_EAI_FAIL;

    while (ai && (rc = uv_tcp_connect(
                    &peer->connect_req_,
                    reinterpret_cast<uv_tcp_t *>(peer->getHandle()),
                    ai->ai_addr,
                    on_active_connection))) {
        LOG(ai ? INFO : WARNING) << "uv_tcp_connect: ["
            << uv_err_name(rc) << "] " << uv_strerror(rc);

        if (swap_stack) {
            switch (rc) {
                case -ECONNABORTED:
                    /* your kernel hates you */
                case -EHOSTUNREACH:
                case -ENETUNREACH:
                case -EADDRNOTAVAIL:
                case -EPROTONOSUPPORT:
                case -EPFNOSUPPORT:
                case -EAFNOSUPPORT:
                case -EPROTOTYPE:
                case -EINVAL:
                case -EBUSY:
                    LOG(INFO) << "destroying socket and retrying";
                    if (!uv_is_closing(peer->getHandle())) {
                        uv_close(peer->getHandle(), swap_stack_on_close);
                    }
                    break;
                 default:
                    LOG(WARNING) << "Unexpected tcp connect rc " << rc;
            }

            return 0;
        }

        ai = ai->ai_next;
        debug_address(ai);
    }

    /* 'ai' is either NULL or the one that is pending... */
    if (!(peer->_.ai_next = ai ? ai->ai_next : NULL)) {
        if(peer->_.ai) { /* on_active_connection(*, -1) could call us again */
            uv_freeaddrinfo(peer->_.ai);
        }
        peer->_.ai = NULL;
    }

    return rc;
}

} /* yajr::comms::internal namespace */
} /* yajr::comms namespace */
} /* yajr namespace */


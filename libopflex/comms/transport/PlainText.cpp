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


#include <opflex/yajr/transport/PlainText.hpp>
#include <opflex/yajr/internal/comms.hpp>

#include <opflex/logging/internal/logging.hpp>

namespace yajr {
namespace transport {

using namespace yajr::comms::internal;

static TransportEngine< PlainText > PlainTextCookieCutterEngine(NULL);

TransportEngine< PlainText > & PlainText::getPlainTextTransport() {
    return PlainTextCookieCutterEngine;
}

template<>
int Cb< PlainText >::send_cb(CommunicationPeer * peer) {
    assert(!peer->getPendingBytes());
    peer->setPendingBytes(peer->getStringQueue().deque_.size());

    if (!peer->getPendingBytes()) {
        /* great success! */
        LOG(TRACE) << "Nothing left to be sent!";
        return 0;
    }

    std::vector<iovec> iov =
        ::yajr::comms::internal::get_iovec(
                peer->getStringQueue().deque_.begin(),
                peer->getStringQueue().deque_.end()
        );

    assert (iov.size());

    return peer->writeIOV(iov);
}

template<>
void Cb< PlainText >::on_sent(CommunicationPeer const * peer) {
    peer->getStringQueue().deque_.erase(
            peer->getStringQueue().deque_.begin(),
            peer->getStringQueue().deque_.begin() + peer->getPendingBytes()
    );
}

template<>
void Cb< PlainText >::alloc_cb(uv_handle_t * _, size_t size, uv_buf_t* buf) {
    // double the size of the buffer
    size_t bufferSize = size * 2;
    *buf = uv_buf_init((char*) malloc(bufferSize), bufferSize);
}

template<>
void Cb< PlainText >::on_read(uv_stream_t * h, ssize_t nread, uv_buf_t const * buf) {
    CommunicationPeer * peer = comms::internal::Peer::get<CommunicationPeer>(h);

    if (!peer->connected_) {
        return;
    }

    if (nread < 0) {
        LOG(DEBUG)
            << peer << " nread = " <<  nread << " ["
            << uv_err_name(nread) << "] "
            << uv_strerror(nread) << " => closing";
        peer->onDisconnect();
    }

    if (nread > 0) {
        if (peer->nullTermination) {
            peer->readBuffer(
                buf->base,
                nread,
                (buf->len > static_cast< size_t >(nread))
            );
        } else {
            // add null terminator to indicate end of message
            if (buf->len > (size_t)nread) {
                buf->base[nread++] = '\0';
            }
            peer->readBufNoNull(buf->base, nread);
        }
    }

    if (buf->base) {
        free(buf->base);
    }

}

} /* yajr::transport namespace */
} /* yajr namespace */

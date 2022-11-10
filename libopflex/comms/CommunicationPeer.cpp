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

#include <cstdlib>
#include <yajr/rpc/gen/echo.hpp>
#include <yajr/rpc/internal/json_stream_wrappers.hpp>
#include <yajr/rpc/methods.hpp>

#include <rapidjson/error/en.h>

template<>
int yajr::AsyncDocumentParser<>::instance_count_ = 0;

namespace yajr {
    namespace internal {

        bool isLegitPunct(int c) {

            switch(c) {
                case '\0':
                case  ' ':
                case  '"':
                case  '%':
                case  ',':
                case  '-':
                case  '.':
                case  '/':
                case  ':':
                case  '[':
                case  ']':
                case  '_':
                case  '{':
                case  '|':
                case  '}':
                case  '\\':
                case  '(': 
                case  ')': 
                case  '<': 
                case  '>': 
                case  '$':
                case  '\n':
                case  '\t':
                case  '\r':
                case  '!':
                case  '#':
                case  '&':
                case  '*':
                case  '+':
                case  '\'':
                case  ';':
                case  '=':
                case  '?':
                case  '^':
                case  '`':
                case  '@':
                case  '~':
                    return true;

                default:
                    return (
                        (c & 0xe0)             // ASCII from 1 to 31 are BAD
                    &&
                        std::isalnum(c)        // alphanumeric values are GOOD
                    );
            }
        }
    }
    namespace comms {
        namespace internal {

void CommunicationPeer::startKeepAlive(
        uint64_t begin,
        uint64_t repeat,
        uint64_t timeoutAfter) {
    LOG(DEBUG) << this << " timeoutAfter=" << timeoutAfter << " begin=" << begin << " repeat=" << repeat;

    sendEchoReq();
    bumpLastHeard();

    keepAliveInterval_ = timeoutAfter;
    uv_timer_start(&keepAliveTimer_, on_timeout, begin, repeat);
}

void CommunicationPeer::stopKeepAlive() {
    LOG(DEBUG)<< this;
    uv_timer_stop(&keepAliveTimer_);
    keepAliveInterval_ = 0;
}

void CommunicationPeer::on_timeout(uv_timer_t * timer) {
    get(timer)->timeout();
}

void CommunicationPeer::bumpLastHeard() const {
    lastHeard_ = now();
}

void CommunicationPeer::onConnect() {
    connected_ = true;
    status_ = internal::Peer::kPS_ONLINE;

    keepAliveTimer_.data = this;
    LOG(DEBUG) << this << " up() for a timer init";
    up();
    uv_timer_init(getUvLoop(), &keepAliveTimer_);
    uv_unref((uv_handle_t*) &keepAliveTimer_);

    connectionHandler_(this, data_, ::yajr::StateChange::CONNECT, 0);

    /* some transports, like for example SSL/TLS, need to start talking
     * before there's anything to say */
    (void) write();
}

void CommunicationPeer::onDisconnect() {
    LOG(DEBUG) << this << " connected_ = " << connected_;
    if (!uv_is_closing(getHandle())) {
        uv_close(getHandle(), on_close);
    }

    if (connected_) {
        /* wipe deque out and reset pendingBytes_ */
        s_.deque_.clear();
        pendingBytes_ = 0;
        connected_ = false;

        resetSsIn();

        if (getKeepAliveInterval()) {
            stopKeepAlive();
        }

        if (!uv_is_closing((uv_handle_t*)&keepAliveTimer_)) {
            uv_close((uv_handle_t*)&keepAliveTimer_, on_close);
        }
        connectionHandler_(this, data_, ::yajr::StateChange::DISCONNECT, 0);
    }

    unlink();

    if (destroying_) {
        LOG(DEBUG) << this << " already destroying";
        return;
    }

    if (!passive_) {
        LOG(DEBUG) << this << " active => retry queue";
        /* we should attempt to reconnect later */
        insert(internal::Peer::LoopData::RETRY_TO_CONNECT);
        status_ = kPS_DISCONNECTED;
    } else {
        LOG(DEBUG) << this << " passive => eventually drop";
        /* whoever it was, hopefully will reconnect again */
        insert(internal::Peer::LoopData::PENDING_DELETE);
        status_ = kPS_PENDING_DELETE;
    }
}

void CommunicationPeer::destroy(bool now) {
    destroying_ = true;
    onDisconnect();
}

int CommunicationPeer::tcpInit() {
    int rc;
    if ((rc = uv_tcp_init(getUvLoop(), reinterpret_cast<uv_tcp_t *>(getHandle())))) {
        LOG(WARNING) << "uv_tcp_init: [" << uv_err_name(rc) << "] " << uv_strerror(rc);
        return rc;
    }

    if ((rc = uv_tcp_keepalive(reinterpret_cast<uv_tcp_t *>(getHandle()), 1, 60))) {
        LOG(WARNING) << "uv_tcp_keepalive: [" << uv_err_name(rc) << "] " << uv_strerror(rc);
    }

    if ((rc = uv_tcp_nodelay(reinterpret_cast<uv_tcp_t *>(getHandle()), 1))) {
        LOG(WARNING) << "uv_tcp_nodelay: [" << uv_err_name(rc) << "] " << uv_strerror(rc);
    }

    return 0;
}

int CommunicationPeer::asyncDocParserCb(rapidjson::Document &d) {
    if (d.HasParseError()) {
        rapidjson::ParseErrorCode e = d.GetParseError();
        size_t o = d.GetErrorOffset();
        LOG(ERROR)
            << "Error: " << rapidjson::GetParseError_En(e) << " at offset "
            << o << " of message (" << asyncDocParser_.Getbuf() << ")";
        LOG(ERROR)
            << "unprocessed part (" << asyncDocParser_.GetUnparsedbuf() << ")"
            << ", count " << asyncDocParser_.Tell()
            << ", instance " << asyncDocParser_.GetInstance()
            << ", allocs " << asyncDocParser_.GetAllocs();
        onError(UV_EPROTO);
        onDisconnect();
        return -1;
    } else {
        LOG(DEBUG) << "Success Parsing, count " <<  asyncDocParser_.Tell()
                   << "(" << asyncDocParser_.Getbuf() << ")"
                   << ", instance " << asyncDocParser_.GetInstance()
                   << ", allocs " << asyncDocParser_.GetAllocs();
        auto inb = yajr::rpc::MessageFactory::getInboundMessage(*this, d);
        if (!inb) {
            LOG(ERROR)
                << "Error: in getInboundMessage for document ("
                << asyncDocParser_.Getbuf() << ")"
                << ", count " << asyncDocParser_.Tell()
                << ", instance " << asyncDocParser_.GetInstance()
                << ", allocs " << asyncDocParser_.GetAllocs();
            onError(UV_EPROTO);
            onDisconnect();
        }
        std::unique_ptr<yajr::rpc::InboundMessage> msg(inb);
        if (!msg) {
            LOG(ERROR)
                << "Error: in composing message for document ("
                << asyncDocParser_.Getbuf() << ")"
                << ", count " << asyncDocParser_.Tell()
                << ", instance " << asyncDocParser_.GetInstance()
                << ", allocs " << asyncDocParser_.GetAllocs();
            LOG(ERROR) << "Skipping inbound message";
            return 0;
        }
        msg->process();
        return 0;
    }
}

void CommunicationPeer::readBufNoNull(char* buffer, size_t nread) {
    if (!nread) {
        return;
    }

    if (std::getenv("OVS_USE_ASYNC_JSON")) {
        bumpLastHeard();
        int ret = asyncDocParser_.ParsePart(buffer, nread);
        if (ret < 0) {
            LOG(ERROR) << "Error ParsePart for message ("
                       << buffer << ") Length " << nread
                       << ", instance " << asyncDocParser_.GetInstance()
                       << ", allocs " << asyncDocParser_.GetAllocs();
        } else {
            LOG(DEBUG) << "ParsePart of length " << nread
                       << "(" << buffer << ")"
                       << ", instance " << asyncDocParser_.GetInstance()
                       << ", allocs " << asyncDocParser_.GetAllocs();
        }
        return;
    }

    while ((nread != 0 && --nread > 0) && connected_) {
        size_t chunk_size = readChunk(buffer);
        if (chunk_size == 0) {
            break;
        }
        nread -= chunk_size++;
        buffer += chunk_size;

        bumpLastHeard();

        yajr::comms::internal::wrapper::IStreamWrapper is(ssIn_);
        while (is.Peek()) {
            docIn_.GetAllocator().Clear();
            docIn_.ParseStream<rapidjson::kParseStopWhenDoneFlag>(is);
            if (docIn_.HasParseError()) {
                rapidjson::ParseErrorCode e = docIn_.GetParseError();
                size_t o = docIn_.GetErrorOffset();
                LOG(ERROR)
                    << "Error: " << rapidjson::GetParseError_En(e) << " at offset "
                    << o << " of message: (" << ssIn_.str() << ")";
                if (ssIn_.str().data()) {
                    onError(UV_EPROTO);
                    onDisconnect();
                }
            } else {
                auto inb = yajr::rpc::MessageFactory::getInboundMessage(*this, docIn_);
                if (!inb) {
                    onError(UV_EPROTO);
                    onDisconnect();
                }
                std::unique_ptr<yajr::rpc::InboundMessage> msg(inb);
                if (!msg) {
                    LOG(ERROR) << "skipping inbound message";
                    continue;
                }
                msg->process();
            }
        }
    }
    resetSsIn();
}

void CommunicationPeer::readBuffer(char * buffer, size_t nread, bool canWriteJustPastTheEnd) {
    if (!nread) {
        return;
    }
    char lastByte[2];
    if (!canWriteJustPastTheEnd) {
        lastByte[0] = buffer[nread-1];

        if (nread > 1) {  /* just as an optimization */
            buffer[nread-1] = '\0';
            readBufferZ(buffer, nread);
        }

        nread = 1;
        buffer = lastByte;
    }

    buffer[nread++] = '\0';
    readBufferZ(buffer, nread);
}

void CommunicationPeer::readBufferZ(char const * buffer, size_t nread) {
    if (!connected_) {
        LOG(WARNING) << "skipping read as not connected";
    }

    if (std::getenv("OPFLEX_USE_ASYNC_JSON")) {
        if (!nread) {
            return;
        }

        bumpLastHeard();
        int ret = asyncDocParser_.ParsePart(buffer, nread);
        if (ret < 0) {
            LOG(ERROR) << "Error ParsePart for message ("
                       << buffer
                       << "), length " << nread
                       << ", instance " << asyncDocParser_.GetInstance()
                       << ", allocs " << asyncDocParser_.GetAllocs();
        } else {
            LOG(DEBUG) << "ParsePart of length " << nread
                       << "(" << buffer << ")"
                       << ", instance " << asyncDocParser_.GetInstance()
                       << ", allocs " << asyncDocParser_.GetAllocs();
        }
        return;
    }

    while ((--nread > 0) && connected_) {
        size_t chunk_size = readChunk(buffer);
        nread -= chunk_size++;

        if (!nread) {
            break;
        }

        buffer += chunk_size;
        std::unique_ptr<yajr::rpc::InboundMessage> msg(parseFrame());

        if (!msg) {
            LOG(ERROR) << "skipping inbound message";
            continue;
        }
        msg->process();
    }
}

void CommunicationPeer::onWrite() {
    transport_.callbacks_->onSent_(this);
    pendingBytes_ = 0;
    write(); /* kick the can */
}

int CommunicationPeer::write() {
    if (pendingBytes_) {
        return 0;
    }

    return transport_.callbacks_->sendCb_(this);
}

int CommunicationPeer::writeIOV(std::vector<iovec>& iov) const {
    assert(!iov.empty());

    int rc;
    if ((rc = uv_write(
                    &write_req_,
                    (uv_stream_t*) getHandle(),
                    (uv_buf_t*)&iov[0],
                    iov.size(),
                    on_write))) {
        LOG(ERROR) << this << "uv_write: [" << uv_err_name(rc) << "] " << uv_strerror(rc);
        onError(rc);
        const_cast<CommunicationPeer *>(this)->onDisconnect();
    } else {
        const_cast<CommunicationPeer *>(this)->up();
    }

    return rc;
}

bool EchoGen::operator() (rpc::SendHandler & handler) const {
    if (!handler.StartArray()) {
        return false;
    }

    if (!handler.Uint64(peer_.now())) {
        return false;
    }

    return handler.EndArray();
}

void CommunicationPeer::sendEchoReq() {
    yajr::rpc::OutReq< &rpc::method::echo > (
            EchoGen(*this),
            this
        )
        . send();
}

void CommunicationPeer::timeout() {
    uint64_t rtt = now() - lastHeard_;

    if (uvRefCnt_ == 1) {
        /* we already have a pending close */
        LOG(TRACE) << this << " Already closing";
        return;
    }

    if (rtt > keepAliveInterval_) {
        LOG(WARNING) << this << " tearing down the connection upon timeout";
        /* close the connection and hope for the best */
        this->onDisconnect();
        return;
    }

    /* send echo request */
    sendEchoReq();
}

int comms::internal::CommunicationPeer::choke() const {
    if (choked_) {
        LOG(WARNING) << this << " already choked";
        return 0;
    }

    int rc;
    if ((rc = uv_read_stop((uv_stream_t*) getHandle()))) {
        LOG(WARNING) << "uv_read_stop: [" << uv_err_name(rc) << "] " << uv_strerror(rc);
        onError(rc);
        const_cast<CommunicationPeer *>(this)->onDisconnect();
    } else {
        choked_ = 1;
    }

    return rc;
}

int comms::internal::CommunicationPeer::unchoke() const {
    if (!choked_) {
        LOG(WARNING) << this << " already unchoked";
        return 0;
    }

    int rc;
    if ((rc = uv_read_start(
                    (uv_stream_t*) getHandle(),
                    transport_.callbacks_->allocCb_,
                    transport_.callbacks_->onRead_)
    )) {
        LOG(WARNING) << "uv_read_start: [" << uv_err_name(rc) << "] " << uv_strerror(rc);
        onError(rc);
        const_cast<CommunicationPeer *>(this)->onDisconnect();
    } else {
        choked_ = 0;
    }

    return rc;
}

yajr::rpc::InboundMessage * comms::internal::CommunicationPeer::parseFrame() {
    bumpLastHeard();

    /* empty frames are legal too */
    if (ssIn_.str().empty()) {
        return NULL;
    }

    yajr::rpc::InboundMessage * ret = NULL;
    yajr::comms::internal::wrapper::IStreamWrapper is(ssIn_);

    docIn_.GetAllocator().Clear();

    docIn_.ParseStream(is);
    if (docIn_.HasParseError()) {
        rapidjson::ParseErrorCode e = docIn_.GetParseError();
        size_t o = docIn_.GetErrorOffset();

        LOG(ERROR)
            << "Error: " << rapidjson::GetParseError_En(e) << " at offset "
            << o << " of message: (" << ssIn_.str() << ")";

        if (ssIn_.str().data()) {
            onError(UV_EPROTO);
            onDisconnect();
        }

        // ret stays set to NULL
    } else {
        /* don't clean up ssIn_ yet. yes, it's technically a "dead" variable here,
         * but we might need to inspect it from gdb to make our life easier when
         * getInboundMessage() isn't happy :)
         */
        ret = yajr::rpc::MessageFactory::getInboundMessage(*this, docIn_);
        if (!ret) {
            onError(UV_EPROTO);
            onDisconnect();
        }
    }

    resetSsIn();
    return ret;
}

} // namespace internal
} // namespace comms
} // namespace yajr


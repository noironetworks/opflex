/*
 * Copyright (c) 2022 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * Adopted from rapidjson/examples/parsebyparts.cpp
 * Modified to make it a continuous stream parser that keeps
 * parsing into a single document internal to the parser and
 * invokes a callback after each successful parse. On error
 * the parser resets the stream to empty and continues the
 * parse. user is expected to tell the other end to restart
 * the parse. The parser treats '\0' as end of parse, hence
 * null characters in the stream are skipped. The parse stops
 * when the object is destroyed.
 *
 * Currently the parser only supports one writer per object. A single
 * reader thread is also created per object.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef _INCLUDE__YAJR__ASYNC_DOC_PARSER_HPP
#define _INCLUDE__YAJR__ASYNC_DOC_PARSER_HPP

#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/writer.h"
#include "rapidjson/ostreamwrapper.h"
#include <condition_variable>
#include <iostream>
#include <sstream>
#include <fstream>
#include <mutex>
#include <thread>
#include <functional>
#include <sys/types.h>
#include <unistd.h>
#include <atomic>

namespace yajr {

using namespace rapidjson;

template<unsigned parseFlags = kParseStopWhenDoneFlag>
class AsyncDocumentParser {
public:
    static std::atomic<int> instance_count_;
    explicit AsyncDocumentParser(std::function<int(Document& d)> cb)
        : stream_(*this)
        , d_()
        , cb_(cb)
        , parseThread_()
        , mutex_()
        , notEmpty_()
        , finish_()
        , stop_()
        , id_(instance_count_.load(std::memory_order_relaxed))
    {
        // Create and execute thread after all member variables are initialized.
        parseThread_ = std::thread(&AsyncDocumentParser::Parse, this);
        std::string fname = "/var/log/opflex-json.log." + std::to_string(getpid()) + "." + std::to_string(instance_count_);
        out_.open(fname, std::ofstream::out | std::ofstream::app);
        instance_count_++;
    }

    ~AsyncDocumentParser() {
        if (!parseThread_.joinable())
            return;

        {
            std::unique_lock<std::mutex> lock(mutex_);

            stop_ = true;
            instance_count_--;
            notEmpty_.notify_one();
        }

        parseThread_.join();
        if (stream_.buf_)
            free(stream_.buf_);
    }

    int ParsePart(const char* buffer, size_t length) {

        std::unique_lock<std::mutex> lock(mutex_);

        // Wait until the buffer is read up (or parsing is completed)
        while (!stream_.Empty())
            finish_.wait(lock);

        // Set the buffer to stream and unblock the AsyncStringStream
        if (!stream_.buf_ || length > stream_.buflen_) {
            stream_.buf_ = (char *)realloc(stream_.buf_, length + 1);
            stream_.buflen_ = length;
            stream_.alloccnt_++;
        }

        if (!stream_.buf_)
            return -1;

        memcpy(stream_.buf_, buffer, length);
        *(char *)(stream_.buf_ + length) = '\0';
        stream_.src_ = stream_.buf_;
        stream_.end_ = stream_.buf_ + length;
        notEmpty_.notify_one();

        return 0;
    }

    const char* Getbuf() { return stream_.buf_; }

    const char* GetUnparsedbuf() { return stream_.src_; }

    int Tell() { return stream_.count_; }

    int GetAllocs() { return stream_.alloccnt_; }

    int GetInstance() { return id_; }
private:
    void Parse() {
        while (true) {
            d_.ParseStream<parseFlags>(stream_);

            // The stream may not be fully read, notify finish anyway to unblock ParsePart()
            std::unique_lock<std::mutex> lock(mutex_);

            if (stop_)
                break;

            cb_(d_);

            // The user should reset the other side
            if (d_.HasParseError())
                stream_.src_ = stream_.end_;

            //out_.put('\n');
            //out_.flush();
            d_.SetNull();
            d_.GetAllocator().Clear();
            finish_.notify_one();   // Unblock ParsePart() or destructor if they are waiting.
       }
    }

    struct AsyncStringStream {
        typedef char Ch;

        explicit AsyncStringStream(AsyncDocumentParser& parser) : parser_(parser), buf_(), buflen_(), src_(), end_(), count_(), alloccnt_() {}
        char Peek() {
            std::unique_lock<std::mutex> lock(parser_.mutex_);

            // Skip '\0'
            while (!Empty() && *src_ == '\0')
                src_++;

            if (Empty())
                parser_.finish_.notify_one();

            // If nothing in stream, block to wait.
            while (Empty() && !parser_.stop_)
                parser_.notEmpty_.wait(lock);

            if (parser_.stop_)
                return '\0';

            return *src_;
        }

        char Take() {
            std::unique_lock<std::mutex> lock(parser_.mutex_);

            // Skip '\0'
            while (!Empty() && *src_ == '\0')
                src_++;

            if (Empty())
                parser_.finish_.notify_one();

            // If nothing in stream, block to wait.
            while (Empty() && !parser_.stop_)
                parser_.notEmpty_.wait(lock);

            if (parser_.stop_)
                return '\0';

            count_++;
            char c = *src_++;
            //parser_.out_.put(c);
            //parser_.out_.flush();

            // If all stream is read up, notify that the stream is finish.
            if (Empty())
                parser_.finish_.notify_one();

            return c;
        }

        size_t Tell() const { return count_; }

        // Not implemented
        char* PutBegin() { return 0; }
        void Put(char) {}
        void Flush() {}
        size_t PutEnd(char*) { return 0; }

        bool Empty() const { return src_ == end_; }

        AsyncDocumentParser& parser_;
        char *buf_;
        size_t buflen_;
        const char* src_;     //!< Current read position.
        const char* end_;     //!< End of buffer
        size_t count_;        //!< Number of characters taken so far.
        size_t alloccnt_;
    };

    AsyncStringStream stream_;
    Document d_;
    std::function<int(Document& d)> cb_;
    std::thread parseThread_;
    std::mutex mutex_;
    std::condition_variable notEmpty_;
    std::condition_variable finish_;
    bool stop_;
    int id_;
    std::ofstream out_;
};

} /* yajr namespace */

#endif /* _INCLUDE__YAJR__ASYNC_DOC_PARSER_HPP */

/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for ofobjectlistener.
 *
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


#include "opflex/logging/OFLogHandler.h"
#include "opflex/c/ofloghandler_c.h"

using opflex::logging::OFLogHandler;

static int getLevel(OFLogHandler::Level level) {
    switch (level) {
    case OFLogHandler::FATAL:
        return LOG_FATAL;
    case OFLogHandler::ERROR:
        return LOG_ERROR;
    case OFLogHandler::WARNING:
        return LOG_WARNING;
    case OFLogHandler::INFO:
        return LOG_INFO;
    case OFLogHandler::TRACE:
    default:
        return LOG_TRACE;
    }
}

static OFLogHandler::Level getLevel(int level) {
    switch (level) {
    case LOG_INFO:
        return OFLogHandler::INFO;
    case LOG_WARNING:
        return OFLogHandler::WARNING;
    case LOG_ERROR:
        return OFLogHandler::ERROR;
    case LOG_FATAL:
        return OFLogHandler::FATAL;
    case LOG_TRACE:
    default:
        return OFLogHandler::TRACE;
    }
}


class COFLogHandler : public OFLogHandler {
public:
    COFLogHandler(Level level, loghandler_p callback_)
        : OFLogHandler(level), callback(callback_) {}

    virtual ~COFLogHandler() {}

    virtual void handleMessage(const std::string& file,
                               const int line,
                               const std::string& function,
                               const Level level,
                               const std::string& message) {
        callback(file.c_str(), line, function.c_str(),
                 getLevel(level), message.c_str());
    }

    loghandler_p callback;
};

static COFLogHandler logHandler(OFLogHandler::NO_LOGGING, NULL);

ofstatus ofloghandler_register(int level, loghandler_p callback) {
    if (callback == NULL)
        return OF_EINVALID_ARG;

    logHandler = COFLogHandler(getLevel(level), callback);
    OFLogHandler::registerHandler(logHandler);
    return OF_ESUCCESS;
}

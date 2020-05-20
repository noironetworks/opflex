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


#include <opflex/yajr/internal/comms.hpp>

#include <opflex/logging/internal/logging.hpp>

namespace yajr {
    namespace comms {
        namespace internal {

void ActivePeer::destroy(bool now) {
    bool alreadyBeingDestroyed = destroying_;

    if (!alreadyBeingDestroyed || now) {
        CommunicationPeer::destroy(now);
    }

    if (alreadyBeingDestroyed) {
        LOG(DEBUG1) << this << " multiple destroy()s detected";
        return;
    }

    down();
}

} // namespace internal
} // namespace comms
} // namespace yajr


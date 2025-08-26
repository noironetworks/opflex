/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for out of band config
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEXAGENT_OUTOFBANDCONFIG_H
#define OPFLEXAGENT_OUTOFBANDCONFIG_H

namespace opflexagent {
    class OutOfBandConfigSpec {
        public:
            OutOfBandConfigSpec(long intvl):tunnelEpAdvInterval(intvl) {};
            long tunnelEpAdvInterval;
    };
} /* namespace opflexagent */

#endif /* OPFLEXAGENT_OUTOFBANDCONFIG_H */

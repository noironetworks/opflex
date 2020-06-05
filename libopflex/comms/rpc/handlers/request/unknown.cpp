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


#include <yajr/rpc/methods.hpp>

namespace yajr {
    namespace rpc {

template<>
void InbReq<&yajr::rpc::method::unknown>::process() const {
    if (getPayload().IsArray()) {
        for (rapidjson::Value::ConstMemberIterator
                 itr = getPayload().MemberBegin(); itr != getPayload().MemberEnd(); ++itr) {
            if (itr->value.IsString()) {
                LOG(INFO) << "String " << itr->value.GetString();
            } else if (itr->value.IsObject()) {
                LOG(INFO) << "IsObject";
                if (itr->value.HasMember("method") && itr->value["method"].IsString()) {
                    LOG(WARNING) << "Received method name " << itr->value["method"].GetString();
                }
            }
        }
        LOG(WARNING) << "Finished iterating";
    } else {
        LOG(WARNING) << "Received unknown method request";
    }
}

}
}


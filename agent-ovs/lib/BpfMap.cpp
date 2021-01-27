/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for Bpf class
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/BpfMap.h>
#include <opflexagent/logging.h>

#include <cstring>
#include <errno.h>
#include <sys/resource.h>

namespace opflexagent {

BpfMap::BpfMap(const std::string& map_name,
               enum ProgType prog_type,
               enum bpf_map_type type,
               uint32_t size_key,
               uint32_t size_value,
               uint32_t max_elem,
               uint32_t flags)
    : fd(-1), name(map_name) {
    mapAttr = {};
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        LOG(ERROR) << "error setting rlimit " << strerror(errno);
        return;
    }
    /*
     * Try to open an existing map
     */
    if (prog_type == XDP)
        map_prefix = "/sys/fs/bpf/xdp/globals/";
    else if (prog_type == TC)
        map_prefix = "/sys/fs/bpf/tc/globals/";
    else {
        LOG(ERROR) << "unrecognized program type "
                  << prog_type << " for map "<< map_name;
        return;
    }

    std::string path = map_prefix + map_name;
    mapAttr.pathname = uintptr_t(path.c_str());
    fd = sysCall(BPF_OBJ_GET, &mapAttr);

    if (fd >= 0) {
        mapAttr.map_type = type;
        mapAttr.key_size = size_key;
        mapAttr.value_size = size_value;
        mapAttr.max_entries = max_elem;
        mapAttr.map_flags = flags;
        LOG(DEBUG) << "successfully opened map " << name
		  << " fd " << fd;
    } else {
        LOG(ERROR) << "Could not open map " << name
                   << " error: " << strerror(errno);
    }
}

BpfMap::~BpfMap() {
    if (fd >= 0)
        ::close(fd);
    fd = -1; 
}

int BpfMap::updateElem(const void *key,
                       const void *value,
                       uint64_t flags) {
    union bpf_attr attr = {};

    
    if (fd < 0) {
        std::string path = map_prefix + name;
        attr.pathname = uintptr_t(path.c_str());
        fd = sysCall(BPF_OBJ_GET, &attr);
        if (fd < 0) {
	    LOG(ERROR) << "update(get) failed for map " << path
                       << " fd " << fd << " " << strerror(errno);
            return -1;
        }
    }

    attr.map_fd = fd;
    attr.key = uintptr_t(key);
    attr.value = uintptr_t(value);
    attr.flags = flags;

    LOG(DEBUG) << "updating BPF fd " << fd;
    return sysCall(BPF_MAP_UPDATE_ELEM, &attr);
}

int BpfMap::lookupElem(const void *key,
                       void *value) {
    union bpf_attr attr = {};

    attr.map_fd = fd;
    attr.key = uintptr_t(key);
    attr.value = uintptr_t(value);

    return sysCall(BPF_MAP_LOOKUP_ELEM, &attr);
}

int BpfMap::lookupDeleteElem(const void *key,
                             void *value) {
    union bpf_attr attr = {};

    attr.map_fd = fd;
    attr.key = uintptr_t(key);
    attr.value = uintptr_t(value);

    return sysCall(BPF_MAP_LOOKUP_AND_DELETE_ELEM, &attr);
}

int BpfMap::deleteElem(const void *key) {
    union bpf_attr attr = {};

    attr.map_fd = fd;
    attr.key = uintptr_t(key);

    return sysCall(BPF_MAP_DELETE_ELEM, &attr);
}

int BpfMap::getNextKey(const void *key,
                       void *next_key) {
    union bpf_attr attr = {};

    attr.map_fd = fd;
    attr.key = uintptr_t(key);
    attr.next_key = uintptr_t(next_key);

    return sysCall(BPF_MAP_GET_NEXT_KEY, &attr);
}
    
void BpfMap::dumpMap(std::ostream &out) {
    void *key = NULL, *prev_key = NULL, *value = NULL;
    int ret, count = 0;

    key = std::calloc(1, mapAttr.key_size);
    if (!key)
        goto done;
    value = std::calloc(1, mapAttr.value_size);
    if (!value)
        goto done;

    while (true) {
        ret = getNextKey(prev_key, key);
        if (ret)
            goto done;

        ret = lookupElem(key, value);
        if (ret)
            goto done;

        dumpElem(out, key, value);
        prev_key = key;
        count++;
    }

done:
    if (key)
        std::free(key);
    if (value)
        std::free(value);
}

#ifndef __NR_bpf
# if defined(__i386__)
#  define __NR_bpf 357
# elif defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# else
#  error __NR_bpf not defined.
# endif
#endif
    
int BpfMap::sysCall(int cmd, union bpf_attr *attr) {
    return ::syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

} /* namespace opflexagent */

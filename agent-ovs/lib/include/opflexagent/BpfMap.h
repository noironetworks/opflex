/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for BpfMap class
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef OPFLEXAGENT_BPFMAP_H
#define OPFLEXAGENT_BPFMAP_H

#include <string>
#include <cstdint>
#include <unistd.h>
#include <linux/bpf.h>

namespace opflexagent {

/**
 * A class for Bpf maps
 */
class BpfMap {
public:
    /**
     * type of BPF program the map is associated with
     */
    enum ProgType {
        TC,
        XDP
    };

    /**
     * Default constructor, opens an existing map
     */
    BpfMap(const std::string& map_name,
           enum ProgType prog_type,
           enum bpf_map_type type,
           uint32_t size_key,
           uint32_t size_value,
           uint32_t max_elem,
           uint32_t flags);

    /**
     * Destructor
     */
    ~BpfMap();

    /**
     * Update an element in the map
     */
    int updateElem(const void *key, const void *value, uint64_t flags = BPF_ANY);

    /**
     * Lookup an element in the map
     */
    int lookupElem(const void *key, void *value);

    /**
     * Lookup and delete an element in the map
     */
    int lookupDeleteElem(const void *key, void *value);

    /**
     * Delete an element in the map
     */
    int deleteElem(const void *key);

    /**
     * Get next key from the map
     */
    int getNextKey(const void *key, void *next_key);

    /**
     * Dump map
     */
    void dumpMap(std::ostream &out);

private:
    /**
     * Dump an element of the map
     */
    virtual void dumpElem(std::ostream &out, const void *key, const void *value) = 0;

    /**
     * syscall interface
     */
    int sysCall(int cmd, union bpf_attr *attr);

    uint32_t fd;
    std::string name;
    std::string map_prefix;
    union bpf_attr mapAttr;
};

}

#endif /* OPFLEXAGENT_BPFMAP_H */

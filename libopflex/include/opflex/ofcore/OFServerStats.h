/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*!
 * @file OFServerStats.h
 * @brief Interface definition file for OFServerStats.h
 */
/*
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#ifndef OPFLEX_OFSERVERSTATS_H
#define OPFLEX_OFSERVERSTATS_H

#include <atomic>

/**
 * OpFlex server stats counters
 */
class OFServerStats {
public:

    /**
     * Create a new instance
     */
    OFServerStats() {};

    /**
     * Destroy the instance
     */
    virtual ~OFServerStats() {};

    /** get the number of identity requests received */
    uint64_t getIdentReqs() { return identReqs; }
    /** increment the number of identity requests received */
    void incrIdentReqs() { identReqs++; }

    /** get the number of policy updates received from gbp server
      * and sent to a connection */
    uint64_t getPolUpdates() { return polUpdates; }
    /** increment the number of policy updates received from gbp server
      * and sent to a connection */
    void incrPolUpdates() { polUpdates++; }

    /** get the number of policies unavilable on received resolve messages */
    uint64_t getPolUnavailableResolves() { return polUnavailableResolves; }
    /** increment the number of policies unavilable on received resolve messages */
    void incrPolUnavailableResolves() { polUnavailableResolves++; }
    /** get the number of policy_resolve msgs received */
    uint64_t getPolResolves() { return polResolves; }
    /** increment the number of policy_resolve msgs received */
    void incrPolResolves() { polResolves++; }
    /** get the number of policy_resolve msgs received errs */
    uint64_t getPolResolveErrs() { return polResolveErrs; }
    /** increment the number of policy_resolve msgs received errs */
    void incrPolResolveErrs() { polResolveErrs++; }

    /** get the number of policy_unresolve msgs received */
    uint64_t getPolUnresolves() { return polUnresolves; }
    /** increment the number of policy_unresolve msgs received */
    void incrPolUnresolves() { polUnresolves++; }
    /** get the number of policy_unresolve msgs received errs */
    uint64_t getPolUnresolveErrs() { return polUnresolveErrs; }
    /** increment the number of policy_unresolve msgs received errs */
    void incrPolUnresolveErrs() { polUnresolveErrs++; }

    /** get the number of endpoint_declare msgs received */
    uint64_t getEpDeclares() { return epDeclares; }
    /** increment the number of endpoint_declare msgs received */
    void incrEpDeclares() { epDeclares++; }
    /** get the number of endpoint_declare msgs received errs */
    uint64_t getEpDeclareErrs() { return epDeclareErrs; }
    /** increment the number of endpoint_declare msgs received errs */
    void incrEpDeclareErrs() { epDeclareErrs++; }

    /** get the number of endpoint_undeclare msgs received */
    uint64_t getEpUndeclares() { return epUndeclares; }
    /** increment the number of endpoint_undeclare msgs received */
    void incrEpUndeclares() { epUndeclares++; }
    /** get the number of endpoint_undeclare msgs received errs */
    uint64_t getEpUndeclareErrs() { return epUndeclareErrs; }
    /** increment the number of endpoint_undeclare msgs received errs */
    void incrEpUndeclareErrs() { epUndeclareErrs++; }

    /** get the number of endpoint_resolve msgs received */
    uint64_t getEpResolves() { return epResolves; }
    /** increment the number of endpoint_resolve msgs received */
    void incrEpResolves() { epResolves++; }
    /** get the number of endpoint_resolve msgs received errs */
    uint64_t getEpResolveErrs() { return epResolveErrs; }
    /** increment the number of endpoint_resolve msgs received errs */
    void incrEpResolveErrs() { epResolveErrs++; }

    /** get the number of endpoint_unresolve msgs received */
    uint64_t getEpUnresolves() { return epUnresolves; }
    /** increment the number of endpoint_unresolve msgs received */
    void incrEpUnresolves() { epUnresolves++; }
    /** get the number of endpoint_unresolve msgs received errs */
    uint64_t getEpUnresolveErrs() { return epUnresolveErrs; }
    /** increment the number of endpoint_unresolve msgs received errs */
    void incrEpUnresolveErrs() { epUnresolveErrs++; }

    /** get the number of state_report msgs received */
    uint64_t getStateReports() { return stateReports; }
    /** increment the number of state_report msgs received */
    void incrStateReports() { stateReports++; }
    /** get the number of state_report msgs received errs */
    uint64_t getStateReportErrs() { return stateReportErrs; }
    /** increment the number of state_report msgs received errs */
    void incrStateReportErrs() { stateReportErrs++; }

private:
    std::atomic_ullong identReqs{};
    std::atomic_ullong polUpdates{};
    std::atomic_ullong polResolves{};
    std::atomic_ullong polResolveErrs{};
    std::atomic_ullong polUnavailableResolves{};
    std::atomic_ullong polUnresolves{};
    std::atomic_ullong polUnresolveErrs{};
    std::atomic_ullong epDeclares{};
    std::atomic_ullong epDeclareErrs{};
    std::atomic_ullong epUndeclares{};
    std::atomic_ullong epUndeclareErrs{};
    std::atomic_ullong epResolves{};
    std::atomic_ullong epResolveErrs{};
    std::atomic_ullong epUnresolves{};
    std::atomic_ullong epUnresolveErrs{};
    std::atomic_ullong stateReports{};
    std::atomic_ullong stateReportErrs{};
};

#endif //OPFLEX_OFSERVERSTATS_H

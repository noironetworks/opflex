#pragma once
#ifndef OPFLEXAGENT_FAULT_H
#define OPFLEXAGENT_FAULT_H

#include <opflex/modb/URI.h>
#include <opflex/modb/MAC.h>

#include <boost/optional.hpp>
#include <modelgbp/fault/SeverityEnumT.hpp>

#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <opflexagent/logging.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
namespace opflexagent {

class Fault {
public:

    Fault() {} 

    /**
     * Set the UUID for this endpoint
     *
     * @param uuid the unique ID for the endpoint
     */
    void setEPUUID(const std::string& uuid) {
        this->ep_uuid = uuid;
    }


    /**
     * Get the UUID for this endpoint
     * @return the unique ID for the endpoint.
     */
    const std::string& getEPUUID() const {
        return ep_uuid;
    }

    /**
     * Set the UUID for this fault raised
     *
     * @param uuid the unique ID for the fault raised
     */
    void setFSUUID(const std::string& uuid) {
        this->fs_uuid = uuid;
    }


    /**
     * Get the UUID for this fault raised
     * @return the unique ID for the fault raised
     */
    const std::string& getFSUUID() const {
        return fs_uuid;
    }

    /**
     * Set the severity for this fault raised
     *
     * @param severity for the fault raised
     */
    void setSeverity(const uint8_t severity) {
        this->severity = severity;
    }


    /**
     * Get the severity for this fault raised
     * @return severity for the fault raised
     */
    const uint8_t getSeverity() const {
        return severity;
    }
 
    /**
     * Set the description for this fault 
     *
     * @param description for the fault 
     */
    void setDescription(const std::string& Description) {
        this->description = Description;
    }
 
     
    /** 
     * Get the description for this fault
     * @return description for the fault 
     */
    const std::string& getDescription() const {
        return description;
    }

    /**
     * Set the fault code
     *
     * @param fault code 
     */
    void setFaultcode(const uint64_t& faultcode) {
        this->faultcode = faultcode;
    }


    /**
     * Get the fault code
     * @return fault code
     */
    const uint64_t& getFaultcode() const {
        return faultcode;
    }

    /**
     * Get the MAC address for this endpoint
     *
     * @return the MAC address
     */
    const boost::optional<opflex::modb::MAC>& getMAC() const {
        return mac;
    }

    /**
     * Set the MAC address for the endpoint
     *
     * @param mac the MAC address
     */
    void setMAC(const opflex::modb::MAC& mac) {
        this->mac = mac;
    }

    /**
     * Set the endpoint group URI associated with this endpoint.  The
     * endpoint group URI controls the policies that are applied to
     * the endpoint.
     *
     * @param egURI the URI to set
     */
    void setEgURI(const opflex::modb::URI& egURI) {
        this->egURI = egURI;
    }

    /**
     * Get the endpoint group associated with this address mapping.
     * This is the endpoint group into which the address mapping
     * address will be mapped.
     *
     * @return the endpoint group URI
     */
    const boost::optional<opflex::modb::URI>& getEgURI() const {
        return egURI;
    }

   private:
      std::string ep_uuid;
      std::string fs_uuid;
      uint64_t faultcode;
      uint8_t severity;
      std::string description;
      boost::optional<opflex::modb::MAC> mac;	
      boost::optional<opflex::modb::URI> egURI;

};

  /**
   * Print fault object to an ostream
   */
    std::ostream & operator<<(std::ostream &os, const Fault& fs);


} /* namespace opflexagent */

#endif /* OPFLEXAGENT_ENDPOINT_H */
 

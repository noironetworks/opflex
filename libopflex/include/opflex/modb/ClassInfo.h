/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*!
 * @file ClassInfo.h
 * @brief Interface definition file for ClassInfo
 */
/*
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef MODB_CLASSINFO_H
#define MODB_CLASSINFO_H

#include <string>
#include <vector>

#include "opflex/modb/PropertyInfo.h"

namespace opflex {
namespace modb {

/**
 * \addtogroup cpp
 * @{
 * \addtogroup metadata
 * @{
 */

/**
 * @brief Class info provides metadata about managed object classes and
 * properties.
 *
 * This metadata is generated by the code generation framework and is
 * required when the framework is initialized.
 */
class ClassInfo {
public:
    /**
     * The type of an MO in the Opflex protocol.  Updates to these MOs
     * will trigger different operations depending on their types.
     */
    enum class_type_t {
        /**
         * An MO describing a configured policy that describes some
         * user intent.  These objects are owned by the policy
         * repository.
         */
        POLICY,

        /**
         * An MO describing a configured policy that describes some
         * user intent.  These objects are owned by the policy
         * element.
         */
        LOCAL_POLICY,
        /**
         * An MO describing a policy enforcement endpoint that
         * resolved from the endpoint registry.  These objects are
         * owned by the endpoint registry and ultimately the remote
         * policy element.
         */
        REMOTE_ENDPOINT,
        /**
         * An MO describing a policy enforcement endpoint that must be
         * registered in the endpoint registry.  These objects are
         * owned and maintained by the local policy element.
         */
        LOCAL_ENDPOINT,
        /**
         * An MO containing information that is reported to the
         * observer.  This could include health information, faults
         * and other status, and statistics related to its parent MO.
         */
        OBSERVABLE,
        /**
         * An MO that exists only locally and will not be transmitted
         * over the OpFlex protocol.
         */
        LOCAL_ONLY,
        /**
         * A type that represents a relationship between two managed
         * objects.  This type would contain a target reference
         * property that will allow the user to resolve related
         * managed objects.
         */
        RELATIONSHIP
    };

    /**
     * A map from a prop_id_t to a PropertyInfo object
     */
    typedef std::unordered_map<prop_id_t, PropertyInfo> property_map_t;

    /**
     * Default constructor
     */
    ClassInfo() : class_id(0), class_type(POLICY) {}

    /**
     * Construct a class info object for the given class ID
     */
    ClassInfo(class_id_t class_id,
              class_type_t class_type,
              const std::string& class_name,
              const std::string& owner,
              const std::vector<PropertyInfo>& properties);

    /**
     * Destroy the class index
     */
    ~ClassInfo();

    /**
     * Get the name for this class
     * @return the name
     */
    const std::string& getName() const { return class_name; }

    /**
     * Get the owner for this class
     * @return the owner string
     */
    const std::string& getOwner() const { return owner; }

    /**
     * Get the unique class ID for this class
     * @return the class ID
     */
    class_id_t getId() const { return class_id; }

    /**
     * Get the type of this class
     * @return the class type
     * @see class_type_t
     */
    class_type_t getType() const { return class_type; }

    /**
     * Get the properties that exist for this class
     * @return A map from prop_id_t to PropertyInfo
     */
    const property_map_t& getProperties() const { return properties; }

    /**
     * Get the PropertyInfo for the given named property
     * @param name the name of the property
     * @return a reference to the property info
     * @throws std::out_of_range if there is no property with that name
     */
    const PropertyInfo& getProperty(const std::string& name) const {
        return properties.at(prop_names.at(name));
    }

    /**
     * Get the PropertyInfo for the given property ID
     * @param prop_id the ID of the property
     * @return a reference to the property info
     * @throws std::out_of_range if there is no property with that ID
     */
    const PropertyInfo& getProperty(prop_id_t& prop_id) const {
        return properties.at(prop_id);
    }

private:
    /**
     * The class ID for this class
     */
    class_id_t class_id;

    /**
     * The type of this class
     */
    class_type_t class_type;

    /**
     * The name for this class
     */
    std::string class_name;

    /**
     * The owner of this class
     */
    std::string owner;

    typedef std::unordered_map<std::string, prop_id_t> prop_name_map_t;

    /**
     * The properties for this class
     */
    property_map_t properties;

    /**
     * Look up properties IDs by name
     */
    prop_name_map_t prop_names;
};

/* @} metadata */
/* @} cpp */

} /* namespace modb */
} /* namespace opflex */

#endif /* MODB_CLASSINFO_H */

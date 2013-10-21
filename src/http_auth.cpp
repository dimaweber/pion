// ---------------------------------------------------------------------
// pion:  a Boost C++ framework for building lightweight HTTP interfaces
// ---------------------------------------------------------------------
// Copyright (C) 2007-2012 Cloudmeter, Inc.  (http://www.cloudmeter.com)
//
// Distributed under the Boost Software License, Version 1.0.
// See http://www.boost.org/LICENSE_1_0.txt
//

#include <boost/algorithm/string.hpp>
#include <pion/http/auth.hpp>
#include <pion/http/server.hpp>


namespace pion {    // begin namespace pion
namespace http {    // begin namespace http


// auth member functions

void auth::add_restrict(const std::string& resource)
{
    boost::mutex::scoped_lock resource_lock(m_resource_mutex);
    const std::string clean_resource(http::server::strip_trailing_slash(resource));
    m_restrict_list.insert(clean_resource);
    PION_LOG_INFO(m_logger, "Set authentication restrictions for HTTP resource: " << clean_resource);
}

void auth::add_permit(const std::string& resource)
{
    boost::mutex::scoped_lock resource_lock(m_resource_mutex);
    const std::string clean_resource(http::server::strip_trailing_slash(resource));
    m_white_list.insert(clean_resource);
    PION_LOG_INFO(m_logger, "Set authentication permission for HTTP resource: " << clean_resource);
}

void auth::add_permit_extension(const std::string& resource)
{
	boost::mutex::scoped_lock resource_lock(m_resource_mutex);
	const std::string clean_resource(http::server::strip_trailing_slash(resource));
	m_whiteext_list.insert(clean_resource);
	PION_LOG_INFO(m_logger, "Set authentication permission extension for HTTP resource: " << clean_resource);
}

void auth::add_force_redirect(const std::string& resource)
{
	boost::mutex::scoped_lock resource_lock(m_resource_mutex);
	const std::string clean_resource(http::server::strip_trailing_slash(resource));
	m_forceredirect_list.insert(clean_resource);
	PION_LOG_INFO(m_logger, "Set redirect force for HTTP resource: " << clean_resource);
}

bool auth::need_redirect(const http::request_ptr& http_request) const
{
	if (!m_omit_redirect)
		return true;

	//if redirect is omited need to check force redirect list
	std::string resource(http::server::strip_trailing_slash(http_request->get_resource()));

	resource_set_type::const_iterator i = m_forceredirect_list.upper_bound(resource);
	while (i != m_forceredirect_list.begin()) {
		--i;
		if (resource == *i)	return true;
	}

	return false;
}

bool auth::need_authentication(const http::request_ptr& http_request_ptr) const
{
    // if no users are defined, authentication is never required
    if (m_user_manager->empty())
        return false;
    
    // strip off trailing slash if the request has one
    std::string resource(http::server::strip_trailing_slash(http_request_ptr->get_resource()));
    
    boost::mutex::scoped_lock resource_lock(m_resource_mutex);
    
    // just return false if restricted list is empty
    if (m_restrict_list.empty())
        return false;

    // try to find resource in restricted list
    if (find_resource(m_restrict_list, resource)) {
		// check white list if it not empty
		if (!m_white_list.empty())
			if (find_resource(m_white_list, resource))
				return false;

		// check also in extension list
		if (!m_whiteext_list.empty())
			if (find_resource_by_extension(m_whiteext_list, resource))
				return false;

		//if not found in both lists
		return true;

		/*// return true if white list is empty
 		if (m_white_list.empty())
 			return true;
 		// return false if found in white list, or true if not found
		return ( ! findResource(m_white_list, resource) );
		return ( ! findResource(m_white_list, resource) );*/

    }
    
    // resource not found in restricted list
    return false;
}

bool auth::find_resource(const resource_set_type& resource_set,
                            const std::string& resource) const
{
    resource_set_type::const_iterator i = resource_set.upper_bound(resource);
    while (i != resource_set.begin()) {
        --i;
        // check for a match if the first part of the strings match
        if (i->empty() || resource.compare(0, i->size(), *i) == 0) {
            // only if the resource matches exactly 
            // or if resource is followed first with a '/' character
            if (resource.size() == i->size() || resource[i->size()]=='/') {
                return true;
            }
        }
    }
    return false;
}

bool auth::find_resource_by_extension(const resource_set_type& resource_set,
							const std::string& resource) const
{
	resource_set_type::const_iterator i;
	for ( i = resource_set.begin() ; i != resource_set.end(); ++i ) {
		//empty permit match all
		if (i->empty()) return true;
		
		//if string ends with resource
		if (resource.size() >= i->size())
			if (resource.compare(resource.size() - i->size(), i->size(), *i) == 0)
				return true;
	}
	return false;
}

  
}   // end namespace http
}   // end namespace pion

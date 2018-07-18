/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.zeppelin.utils

import com.google.common.collect.Sets

import org.apache.shiro.authz.AuthorizationInfo
import org.apache.shiro.realm.Realm
import org.apache.shiro.realm.text.IniRealm
import org.apache.shiro.subject.SimplePrincipalCollection
import org.apache.shiro.subject.Subject
import org.apache.shiro.util.ThreadContext
import org.apache.shiro.web.mgt.DefaultWebSecurityManager
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.net.InetAddress
import java.net.URI
import java.net.URISyntaxException
import java.net.UnknownHostException
import java.security.Principal
import java.util.Collections
import java.util.HashSet

import javax.naming.NamingException

import org.apache.zeppelin.conf.ZeppelinConfiguration
import org.apache.zeppelin.realm.ActiveDirectoryGroupRealm
import org.apache.zeppelin.realm.LdapRealm
import org.apache.zeppelin.server.ZeppelinServer

/**
 * Tools for securing Zeppelin.
 */
object SecurityUtils {
    private val ANONYMOUS = "anonymous"
    private val EMPTY_HASHSET = Sets.newHashSet<String>()
    private var isEnabled = false
    private val log = LoggerFactory.getLogger(SecurityUtils::class.java)

    /**
     * Return the authenticated user if any otherwise returns "anonymous".
     *
     * @return shiro principal
     */
    val principal: String
        get() {
            if (!isEnabled) {
                return ANONYMOUS
            }
            val subject = org.apache.shiro.SecurityUtils.getSubject()

            var principal: String
            if (subject.isAuthenticated) {
                principal = extractPrincipal(subject)
                if (ZeppelinServer.notebook!!.conf.isUsernameForceLowerCase) {
                    log.debug("Converting principal name " + principal
                            + " to lower case:" + principal.toLowerCase())
                    principal = principal.toLowerCase()
                }
            } else {
                principal = ANONYMOUS
            }
            return principal
        }

    val realmsList: Collection<*>
        get() {
            if (!isEnabled) {
                return emptyList<Any>()
            }
            val defaultWebSecurityManager: DefaultWebSecurityManager
            val key = ThreadContext.SECURITY_MANAGER_KEY
            defaultWebSecurityManager = ThreadContext.get(key) as DefaultWebSecurityManager
            return defaultWebSecurityManager.realms
        }

    /**
     * Return the roles associated with the authenticated user if any otherwise returns empty set.
     * TODO(prasadwagle) Find correct way to get user roles (see SHIRO-492)
     *
     * @return shiro roles
     */
    val roles: HashSet<String>
        get() {
            if (!isEnabled) {
                return EMPTY_HASHSET
            }
            val subject = org.apache.shiro.SecurityUtils.getSubject()
            var roles = HashSet<String>()
            var allRoles: Map<*, *>? = null

            if (subject.isAuthenticated) {
                val realmsList = SecurityUtils.realmsList
                val iterator = realmsList.iterator()
                while (iterator.hasNext()) {
                    val realm = iterator.next()
                    val name = realm!!.javaClass.getName()
                    if (name == "org.apache.shiro.realm.text.IniRealm") {
                        allRoles = (realm as IniRealm).ini["roles"]
                        break
                    } else if (name == "org.apache.zeppelin.realm.LdapRealm") {
                        try {
                            val auth = (realm as LdapRealm).queryForAuthorizationInfo(
                                    SimplePrincipalCollection(subject.principal, realm.name),
                                    realm.contextFactory
                            )
                            if (auth != null) {
                                roles = HashSet(auth.roles)
                            }
                        } catch (e: NamingException) {
                            log.error("Can't fetch roles", e)
                        }

                        break
                    } else if (name == "org.apache.zeppelin.realm.ActiveDirectoryGroupRealm") {
                        allRoles = (realm as ActiveDirectoryGroupRealm).listRoles
                        break
                    }
                }
                if (allRoles != null) {
                    val it = allRoles.entries.iterator()
                    while (it.hasNext()) {
                        val pair = it.next()
                        if (subject.hasRole(pair.key as String)) {
                            roles.add(pair.key as String)
                        }
                    }
                }
            }
            return roles
        }

    /**
     * Checked if shiro enabled or not.
     */
    val isAuthenticated: Boolean
        get() = if (!isEnabled) {
            false
        } else org.apache.shiro.SecurityUtils.getSubject().isAuthenticated

    fun setIsEnabled(value: Boolean) {
        isEnabled = value
    }

    @Throws(UnknownHostException::class, URISyntaxException::class)
    fun isValidOrigin(sourceHost: String?, conf: ZeppelinConfiguration): Boolean {

        var sourceUriHost: String? = ""

        if (sourceHost != null && !sourceHost.isEmpty()) {
            sourceUriHost = URI(sourceHost).host
            sourceUriHost = if (sourceUriHost == null) "" else sourceUriHost.toLowerCase()
        }

        sourceUriHost = sourceUriHost!!.toLowerCase()
        val currentHost = InetAddress.getLocalHost().hostName.toLowerCase()

        return conf.allowedOrigins.contains("*") ||
                currentHost == sourceUriHost ||
                "localhost" == sourceUriHost ||
                conf.allowedOrigins.contains(sourceHost)
    }

    private fun extractPrincipal(subject: Subject): String {
        val principal: String
        val principalObject = subject.principal
        if (principalObject is Principal) {
            principal = principalObject.name
        } else {
            principal = principalObject.toString()
        }
        return principal
    }
}

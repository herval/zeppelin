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
package org.apache.zeppelin.realm

import org.apache.shiro.authz.AuthorizationInfo
import org.apache.shiro.authz.SimpleAuthorizationInfo
import org.apache.shiro.realm.ldap.JndiLdapRealm
import org.apache.shiro.realm.ldap.LdapContextFactory
import org.apache.shiro.subject.PrincipalCollection
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.util.HashSet
import java.util.LinkedHashSet

import javax.naming.NamingEnumeration
import javax.naming.NamingException
import javax.naming.directory.Attribute
import javax.naming.directory.Attributes
import javax.naming.directory.SearchControls
import javax.naming.directory.SearchResult
import javax.naming.ldap.LdapContext

/**
 * Created for org.apache.zeppelin.server.
 */
class LdapGroupRealm : JndiLdapRealm() {

    @Throws(NamingException::class)
    public override fun queryForAuthorizationInfo(principals: PrincipalCollection?,
                                                  ldapContextFactory: LdapContextFactory?): AuthorizationInfo {
        val username = getAvailablePrincipal(principals) as String
        val ldapContext = ldapContextFactory!!.systemLdapContext
        val roleNames = getRoleNamesForUser(username, ldapContext, userDnTemplate)
        return SimpleAuthorizationInfo(roleNames)
    }

    @Throws(NamingException::class)
    fun getRoleNamesForUser(username: String, ldapContext: LdapContext,
                            userDnTemplate: String): Set<String> {
        try {
            val roleNames = LinkedHashSet<String>()

            val searchCtls = SearchControls()
            searchCtls.searchScope = SearchControls.SUBTREE_SCOPE

            val searchFilter = "(&(objectClass=groupOfNames)(member=$userDnTemplate))"
            val searchArguments = arrayOf<Any>(username)

            val answer = ldapContext.search(
                    ldapContext.environment["ldap.searchBase"].toString(),
                    searchFilter,
                    searchArguments,
                    searchCtls)

            while (answer.hasMoreElements()) {
                val sr = answer.next() as SearchResult
                val attrs = sr.attributes
                if (attrs != null) {
                    val ae = attrs.all
                    while (ae.hasMore()) {
                        val attr = ae.next() as Attribute
                        if (attr.id == "cn") {
                            roleNames.add(attr.get() as String)
                        }
                    }
                }
            }
            return roleNames

        } catch (e: Exception) {
            LOG.error("Error", e)
        }

        return HashSet()
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(LdapGroupRealm::class.java)
    }
}

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

import java.util.LinkedHashMap
import org.apache.commons.lang.StringUtils
import org.apache.shiro.authc.AuthenticationException
import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.authc.SimpleAuthenticationInfo
import org.apache.shiro.authc.UsernamePasswordToken
import org.apache.shiro.authz.AuthorizationException
import org.apache.shiro.authz.AuthorizationInfo
import org.apache.shiro.authz.SimpleAuthorizationInfo
import org.apache.shiro.realm.ldap.AbstractLdapRealm
import org.apache.shiro.realm.ldap.DefaultLdapContextFactory
import org.apache.shiro.realm.ldap.LdapContextFactory
import org.apache.shiro.realm.ldap.LdapUtils
import org.apache.shiro.subject.PrincipalCollection
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.util.ArrayList
import java.util.HashMap
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
 * A [org.apache.shiro.realm.Realm] that authenticates with an active directory LDAP
 * server to determine the roles for a particular user.  This implementation
 * queries for the user's groups and then maps the group names to roles using the
 * [.groupRolesMap].
 *
 * @since 0.1
 */
class ActiveDirectoryGroupRealm : AbstractLdapRealm() {

    internal val keystorePass = "activeDirectoryRealm.systemPassword"
    private var hadoopSecurityCredentialPath: String? = null

    /**
     * Mapping from fully qualified active directory
     * group names (e.g. CN=Group,OU=Company,DC=MyDomain,DC=local)
     * as returned by the active directory LDAP server to role names.
     */
    private val groupRolesMap = LinkedHashMap<String, String>()

    internal var ldapContextFactory: LdapContextFactory? = null

    private val sysPassword: String
        get() {
            var password = ""
            if (StringUtils.isEmpty(this.hadoopSecurityCredentialPath)) {
                password = super.systemPassword
            } else {
                password = LdapRealm.getSystemPassword(hadoopSecurityCredentialPath!!, keystorePass)
            }
            return password
        }

    val listRoles: Map<String, String>
        get() {
            val roles = HashMap<String, String>()
            val it = this.groupRolesMap.entries.iterator()
            while (it.hasNext()) {
                val pair = it.next()
                roles[pair.value] = "*"
            }
            return roles
        }

    fun setHadoopSecurityCredentialPath(hadoopSecurityCredentialPath: String) {
        this.hadoopSecurityCredentialPath = hadoopSecurityCredentialPath
    }

    fun setGroupRolesMap(groupRolesMap: Map<String, String>) {
        this.groupRolesMap.putAll(groupRolesMap)
    }

    override fun onInit() {
        super.onInit()
        this.getLdapContextFactory()
    }

    fun getLdapContextFactory(): LdapContextFactory {
        if (this.ldapContextFactory == null) {
            if (log.isDebugEnabled()) {
                log.debug("No LdapContextFactory specified - creating a default instance.")
            }

            val defaultFactory = DefaultLdapContextFactory()
            defaultFactory.setPrincipalSuffix(this.principalSuffix)
            defaultFactory.setSearchBase(this.searchBase)
            defaultFactory.setUrl(this.url)
            defaultFactory.setSystemUsername(this.systemUsername)
            defaultFactory.setSystemPassword(this.sysPassword)
            this.ldapContextFactory = defaultFactory
        }

        return this.ldapContextFactory!!
    }

    @Throws(AuthenticationException::class)
    override fun doGetAuthenticationInfo(token: AuthenticationToken): AuthenticationInfo? {
        try {
            return queryForAuthenticationInfo(token,
                    getLdapContextFactory())
        } catch (var5: javax.naming.AuthenticationException) {
            throw AuthenticationException("LDAP authentication failed.", var5)
        } catch (var6: NamingException) {
            val msg = "LDAP naming error while attempting to authenticate user."
            throw AuthenticationException(msg, var6)
        }

    }

    override fun doGetAuthorizationInfo(principals: PrincipalCollection): AuthorizationInfo {
        try {
            return queryForAuthorizationInfo(principals,
                    getLdapContextFactory())
        } catch (var5: NamingException) {
            val msg = "LDAP naming error while attempting to " +
                    "retrieve authorization for user [" + principals + "]."
            throw AuthorizationException(msg, var5)
        }

    }

    /**
     * Builds an [AuthenticationInfo] object by querying the active directory LDAP context for
     * the specified username.  This method binds to the LDAP server using the provided username
     * and password - which if successful, indicates that the password is correct.
     *
     *
     * This method can be overridden by subclasses to query the LDAP server in a more complex way.
     *
     * @param token              the authentication token provided by the user.
     * @param ldapContextFactory the factory used to build connections to the LDAP server.
     * @return an [AuthenticationInfo] instance containing information retrieved from LDAP.
     * @throws NamingException if any LDAP errors occur during the search.
     */
    @Throws(NamingException::class)
    override fun queryForAuthenticationInfo(token: AuthenticationToken,
                                            ldapContextFactory: LdapContextFactory): AuthenticationInfo? {
        val upToken = token as UsernamePasswordToken

        // Binds using the username and password provided by the user.
        var ctx: LdapContext? = null
        try {
            var userPrincipalName = upToken.username
            if (!isValidPrincipalName(userPrincipalName)) {
                return null
            }
            if (this.principalSuffix != null && userPrincipalName.indexOf('@') < 0) {
                userPrincipalName = upToken.username + this.principalSuffix
            }
            ctx = ldapContextFactory.getLdapContext(
                    userPrincipalName, upToken.password)
        } finally {
            LdapUtils.closeContext(ctx)
        }

        return buildAuthenticationInfo(upToken.username, upToken.password)
    }

    private fun isValidPrincipalName(userPrincipalName: String?): Boolean {
        if (userPrincipalName != null) {
            if (StringUtils.isNotEmpty(userPrincipalName) && userPrincipalName.contains("@")) {
                val userPrincipalWithoutDomain = userPrincipalName.split("@".toRegex()).dropLastWhile({ it.isEmpty() }).toTypedArray()[0].trim({ it <= ' ' })
                if (StringUtils.isNotEmpty(userPrincipalWithoutDomain)) {
                    return true
                }
            } else if (StringUtils.isNotEmpty(userPrincipalName)) {
                return true
            }
        }
        return false
    }

    protected fun buildAuthenticationInfo(username: String, password: CharArray): AuthenticationInfo {
        var username = username
        if (this.principalSuffix != null && username.indexOf('@') > 1) {
            username = username.split("@".toRegex()).dropLastWhile({ it.isEmpty() }).toTypedArray()[0]
        }
        return SimpleAuthenticationInfo(username, password, name)
    }

    /**
     * Builds an [org.apache.shiro.authz.AuthorizationInfo] object by querying the active
     * directory LDAP context for the groups that a user is a member of.  The groups are then
     * translated to role names by using the configured [.groupRolesMap].
     *
     *
     * This implementation expects the <tt>principal</tt> argument to be a String username.
     *
     *
     * Subclasses can override this method to determine authorization data (roles, permissions, etc)
     * in a more complex way.  Note that this default implementation does not support permissions,
     * only roles.
     *
     * @param principals         the principal of the Subject whose account is being retrieved.
     * @param ldapContextFactory the factory used to create LDAP connections.
     * @return the AuthorizationInfo for the given Subject principal.
     * @throws NamingException if an error occurs when searching the LDAP server.
     */
    @Throws(NamingException::class)
    override fun queryForAuthorizationInfo(principals: PrincipalCollection,
                                           ldapContextFactory: LdapContextFactory): AuthorizationInfo {
        val username = getAvailablePrincipal(principals) as String

        // Perform context search
        val ldapContext = ldapContextFactory.systemLdapContext

        val roleNames: Set<String>

        try {
            roleNames = getRoleNamesForUser(username, ldapContext)
        } finally {
            LdapUtils.closeContext(ldapContext)
        }

        return buildAuthorizationInfo(roleNames)
    }

    protected fun buildAuthorizationInfo(roleNames: Set<String>): AuthorizationInfo {
        return SimpleAuthorizationInfo(roleNames)
    }

    @Throws(NamingException::class)
    fun searchForUserName(containString: String, ldapContext: LdapContext,
                          numUsersToFetch: Int): List<String> {
        val userNameList = ArrayList<String>()

        val searchCtls = SearchControls()
        searchCtls.searchScope = SearchControls.SUBTREE_SCOPE
        searchCtls.countLimit = numUsersToFetch.toLong()

        val searchFilter = "(&(objectClass=*)(userPrincipalName=*$containString*))"
        val searchArguments = arrayOf<Any>(containString)

        val answer = ldapContext.search(searchBase, searchFilter, searchArguments,
                searchCtls)

        while (answer.hasMoreElements()) {
            val sr = answer.next() as SearchResult

            if (log.isDebugEnabled()) {
                log.debug("Retrieving userprincipalname names for user [" + sr.name + "]")
            }

            val attrs = sr.attributes
            if (attrs != null) {
                val ae = attrs.all
                while (ae.hasMore()) {
                    val attr = ae.next() as Attribute
                    if (attr.id.toLowerCase() == "cn") {
                        userNameList.addAll(LdapUtils.getAllAttributeValues(attr))
                    }
                }
            }
        }
        return userNameList
    }

    @Throws(NamingException::class)
    private fun getRoleNamesForUser(username: String, ldapContext: LdapContext): Set<String> {
        val roleNames = LinkedHashSet<String>()

        val searchCtls = SearchControls()
        searchCtls.searchScope = SearchControls.SUBTREE_SCOPE
        var userPrincipalName = username
        if (this.principalSuffix != null && userPrincipalName.indexOf('@') < 0) {
            userPrincipalName += principalSuffix
        }

        val searchFilter = "(&(objectClass=*)(userPrincipalName=$userPrincipalName))"
        val searchArguments = arrayOf<Any>(userPrincipalName)

        val answer = ldapContext.search(searchBase, searchFilter, searchArguments,
                searchCtls)

        while (answer.hasMoreElements()) {
            val sr = answer.next() as SearchResult

            if (log.isDebugEnabled()) {
                log.debug("Retrieving group names for user [" + sr.name + "]")
            }

            val attrs = sr.attributes

            if (attrs != null) {
                val ae = attrs.all
                while (ae.hasMore()) {
                    val attr = ae.next() as Attribute

                    if (attr.id == "memberOf") {

                        val groupNames = LdapUtils.getAllAttributeValues(attr)

                        if (log.isDebugEnabled()) {
                            log.debug("Groups found for user [$username]: $groupNames")
                        }

                        val rolesForGroups = getRoleNamesForGroups(groupNames)
                        roleNames.addAll(rolesForGroups)
                    }
                }
            }
        }
        return roleNames
    }

    /**
     * This method is called by the default implementation to translate Active Directory group names
     * to role names.  This implementation uses the [.groupRolesMap] to map group names to role
     * names.
     *
     * @param groupNames the group names that apply to the current user.
     * @return a collection of roles that are implied by the given role names.
     */
    protected fun getRoleNamesForGroups(groupNames: Collection<String>): Collection<String> {
        val roleNames = HashSet<String>(groupNames.size)

        if (groupRolesMap != null) {
            for (groupName in groupNames) {
                val strRoleNames = groupRolesMap[groupName]
                if (strRoleNames != null) {
                    for (roleName in strRoleNames.split(ROLE_NAMES_DELIMETER.toRegex()).dropLastWhile({ it.isEmpty() }).toTypedArray()) {

                        if (log.isDebugEnabled()) {
                            log.debug("User is member of group [" + groupName + "] so adding role [" +
                                    roleName + "]")
                        }

                        roleNames.add(roleName)

                    }
                }
            }
        }
        return roleNames
    }

    companion object {
        private val log = LoggerFactory.getLogger(ActiveDirectoryGroupRealm::class.java!!)

        private val ROLE_NAMES_DELIMETER = ","
    }
}

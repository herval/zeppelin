/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.apache.zeppelin.realm

import java.io.IOException
import java.util.ArrayList
import java.util.Collections
import java.util.HashMap
import java.util.HashSet
import java.util.LinkedHashMap
import java.util.LinkedHashSet
import java.util.StringTokenizer
import java.util.regex.Matcher
import java.util.regex.Pattern
import javax.naming.AuthenticationException
import javax.naming.Context
import javax.naming.NamingEnumeration
import javax.naming.NamingException
import javax.naming.PartialResultException
import javax.naming.SizeLimitExceededException
import javax.naming.directory.Attribute
import javax.naming.directory.SearchControls
import javax.naming.directory.SearchResult
import javax.naming.ldap.Control
import javax.naming.ldap.LdapContext
import javax.naming.ldap.LdapName
import javax.naming.ldap.PagedResultsControl
import org.apache.hadoop.conf.Configuration
import org.apache.hadoop.security.alias.CredentialProvider
import org.apache.hadoop.security.alias.CredentialProviderFactory
import org.apache.shiro.SecurityUtils
import org.apache.shiro.ShiroException
import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.authc.SimpleAuthenticationInfo
import org.apache.shiro.authc.credential.HashedCredentialsMatcher
import org.apache.shiro.authz.AuthorizationInfo
import org.apache.shiro.authz.SimpleAuthorizationInfo
import org.apache.shiro.crypto.hash.DefaultHashService
import org.apache.shiro.crypto.hash.Hash
import org.apache.shiro.crypto.hash.HashRequest
import org.apache.shiro.crypto.hash.HashService
import org.apache.shiro.realm.ldap.JndiLdapContextFactory
import org.apache.shiro.realm.ldap.JndiLdapRealm
import org.apache.shiro.realm.ldap.LdapContextFactory
import org.apache.shiro.realm.ldap.LdapUtils
import org.apache.shiro.session.Session
import org.apache.shiro.subject.MutablePrincipalCollection
import org.apache.shiro.subject.PrincipalCollection
import org.apache.shiro.util.StringUtils
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Implementation of [org.apache.shiro.realm.ldap.JndiLdapRealm] that also returns each user's
 * groups. This implementation is heavily based on org.apache.isis.security.shiro.IsisLdapRealm.
 *
 *
 * This implementation saves looked up ldap groups in Shiro Session to make them
 * easy to be looked up outside of this object
 *
 *
 * Sample config for <tt>shiro.ini</tt>:
 *
 *
 *
 * [main]
 * ldapRealm = org.apache.zeppelin.realm.LdapRealm
 * ldapRealm.contextFactory.url = ldap://localhost:33389
 * ldapRealm.contextFactory.authenticationMechanism = simple
 * ldapRealm.contextFactory.systemUsername = uid=guest,ou=people,dc=hadoop,dc= apache,dc=org
 * ldapRealm.contextFactory.systemPassword = S{ALIAS=ldcSystemPassword}
 * ldapRealm.hadoopSecurityCredentialPath = jceks://file/user/zeppelin/zeppelin.jceks
 * ldapRealm.userDnTemplate = uid={0},ou=people,dc=hadoop,dc=apache,dc=org
 * # Ability to set ldap paging Size if needed default is 100
 * ldapRealm.pagingSize = 200
 * ldapRealm.authorizationEnabled = true
 * ldapRealm.searchBase = dc=hadoop,dc=apache,dc=org
 * ldapRealm.userSearchBase = dc=hadoop,dc=apache,dc=org
 * ldapRealm.groupSearchBase = ou=groups,dc=hadoop,dc=apache,dc=org
 * ldapRealm.userObjectClass = person
 * ldapRealm.groupObjectClass = groupofnames
 * # Allow userSearchAttribute to be customized
 * ldapRealm.userSearchAttributeName = sAMAccountName
 * ldapRealm.memberAttribute = member
 * # force usernames returned from ldap to lowercase useful for AD
 * ldapRealm.userLowerCase = true
 * # ability set searchScopes subtree (default), one, base
 * ldapRealm.userSearchScope = subtree;
 * ldapRealm.groupSearchScope = subtree;
 * ldapRealm.userSearchFilter = (&(objectclass=person)(sAMAccountName={0}))
 * ldapRealm.groupSearchFilter = (&(objectclass=groupofnames)(member={0}))
 * ldapRealm.memberAttributeValueTemplate=cn={0},ou=people,dc=hadoop,dc=apache,dc=org
 * # enable support for nested groups using the LDAP_MATCHING_RULE_IN_CHAIN operator
 * ldapRealm.groupSearchEnableMatchingRuleInChain = true
 *
 *
 * # optional mapping from physical groups to logical application roles
 * ldapRealm.rolesByGroup = \ LDN_USERS: user_role,\ NYK_USERS: user_role,\ HKG_USERS: user_role,
 * \GLOBAL_ADMIN: admin_role,\ DEMOS: self-install_role
 *
 *
 * # optional list of roles that are allowed to authenticate
 * ldapRealm.allowedRolesForAuthentication = admin_role,user_role
 *
 *
 * ldapRealm.permissionsByRole=\ user_role = *:ToDoItemsJdo:*:*,\*:ToDoItem:*:*;
 * \ self-install_role = *:ToDoItemsFixturesService:install:* ; \ admin_role = *
 *
 *
 * [urls]
 * **=authcBasic
 *
 *
 * securityManager.realms = $ldapRealm
 */
class LdapRealm : JndiLdapRealm() {

    var searchBase: String? = null
    var userSearchBase: String? = null
        get() = if (field != null && !field!!.isEmpty()) field else searchBase
    var pagingSize = 100
    var userLowerCase: Boolean = false
    /**
     * Set Regex for Principal LDAP.
     *
     * @param regex
     * regex to use to search for principal in shiro.
     */
    var principalRegex: String? = DEFAULT_PRINCIPAL_REGEX
        set(regex) {
            var regex = regex
            if (regex == null || regex.trim { it <= ' ' }.isEmpty()) {
                principalPattern = Pattern.compile(DEFAULT_PRINCIPAL_REGEX)
                field = DEFAULT_PRINCIPAL_REGEX
            } else {
                regex = regex.trim { it <= ' ' }
                val pattern = Pattern.compile(regex)
                principalPattern = pattern
                field = regex
            }
        }
    private var principalPattern = Pattern.compile(DEFAULT_PRINCIPAL_REGEX)
    override fun getUserDnTemplate(): String {
        return "{0}"
    }
    var userSearchFilter: String? = null
        set(filter) {
            field = filter?.trim { it <= ' ' }
        }
    var groupSearchFilter: String? = null
        set(filter) {
            field = filter?.trim { it <= ' ' }
        }
    var userSearchAttributeTemplate: String? = "{0}"
        set(template) {
            field = template?.trim { it <= ' ' }
        }
    var userSearchScope: String? = "subtree"
        set(scope) {
            field = scope?.trim { it <= ' ' }?.toLowerCase()
        }
    var groupSearchScope: String? = "subtree"
        set(scope) {
            field = scope?.trim { it <= ' ' }?.toLowerCase()
        }
    var isGroupSearchEnableMatchingRuleInChain: Boolean = false

    var groupSearchBase: String? = null
        get() = if (field != null && !field!!.isEmpty()) field else searchBase

    var groupObjectClass = "groupOfNames"

    // typical value: member, uniqueMember, memberUrl
    var memberAttribute = "member"

    var groupIdAttribute = "cn"

    private var memberAttributeValuePrefix = "uid="
    private var memberAttributeValueSuffix = ""

    private val rolesByGroup = LinkedHashMap<String, String>()
    private val allowedRolesForAuthentication = ArrayList<String>()
    private val permissionsByRole = LinkedHashMap<String, List<String>>()

    private var hadoopSecurityCredentialPath: String? = null
    internal val keystorePass = "ldapRealm.systemPassword"

    var isAuthorizationEnabled: Boolean = false

    /**
     * Set User Search Attribute Name for LDAP.
     *
     * @param userSearchAttributeName
     * userAttribute to search ldap.
     */
    var userSearchAttributeName: String? = null
        set(userSearchAttributeName) {
            var userSearchAttributeName = userSearchAttributeName
            if (userSearchAttributeName != null) {
                userSearchAttributeName = userSearchAttributeName.trim { it <= ' ' }
            }
            field = userSearchAttributeName
        }
    var userObjectClass = "person"

    private val hashService = DefaultHashService()

    val listRoles: Map<String, String>
        get() {
            val groupToRoles = getRolesByGroup()
            val roles = HashMap<String, String>()
            for ((key, value) in groupToRoles) {
                roles[value] = key
            }
            return roles
        }

    private val userSearchControls: SearchControls
        get() {
            var searchControls = SUBTREE_SCOPE
            if ("onelevel".equals(this.userSearchScope!!, ignoreCase = true)) {
                searchControls = ONELEVEL_SCOPE
            } else if ("object".equals(this.userSearchScope!!, ignoreCase = true)) {
                searchControls = OBJECT_SCOPE
            }
            return searchControls
        }

    val groupSearchControls: SearchControls
        get() {
            var searchControls = SUBTREE_SCOPE
            if ("onelevel".equals(this.groupSearchScope!!, ignoreCase = true)) {
                searchControls = ONELEVEL_SCOPE
            } else if ("object".equals(this.groupSearchScope!!, ignoreCase = true)) {
                searchControls = OBJECT_SCOPE
            }
            return searchControls
        }


    fun setHadoopSecurityCredentialPath(hadoopSecurityCredentialPath: String) {
        this.hadoopSecurityCredentialPath = hadoopSecurityCredentialPath
    }

    init {
        val credentialsMatcher = HashedCredentialsMatcher(HASHING_ALGORITHM)
        setCredentialsMatcher(credentialsMatcher)
    }

    @Throws(org.apache.shiro.authc.AuthenticationException::class)
    override fun doGetAuthenticationInfo(token: AuthenticationToken): AuthenticationInfo {
        try {
            return super.doGetAuthenticationInfo(token)
        } catch (ae: org.apache.shiro.authc.AuthenticationException) {
            throw ae
        }

    }

    override fun onInit() {
        super.onInit()
        if (!org.apache.commons.lang.StringUtils.isEmpty(this.hadoopSecurityCredentialPath) && contextFactory != null) {
            (contextFactory as JndiLdapContextFactory).systemPassword = getSystemPassword(this.hadoopSecurityCredentialPath!!, keystorePass)
        }
    }

    /**
     * This overrides the implementation of queryForAuthenticationInfo inside JndiLdapRealm.
     * In addition to calling the super method for authentication it also tries to validate
     * if this user has atleast one of the allowed roles for authentication. In case the property
     * allowedRolesForAuthentication is empty this check always returns true.
     *
     * @param token the submitted authentication token that triggered the authentication attempt.
     * @param ldapContextFactory factory used to retrieve LDAP connections.
     * @return AuthenticationInfo instance representing the authenticated user's information.
     * @throws NamingException if any LDAP errors occur.
     */
    @Throws(NamingException::class)
    override fun queryForAuthenticationInfo(token: AuthenticationToken,
                                            ldapContextFactory: LdapContextFactory): AuthenticationInfo {
        val info = super.queryForAuthenticationInfo(token, ldapContextFactory)
        // Credentials were verified. Verify that the principal has all allowedRulesForAuthentication
        if (!hasAllowedAuthenticationRules(info.principals, ldapContextFactory)) {
            throw NamingException("Principal does not have any of the allowedRolesForAuthentication")
        }
        return info
    }

    /**
     * Get groups from LDAP.
     *
     * @param principals
     * the principals of the Subject whose AuthenticationInfo should
     * be queried from the LDAP server.
     * @param ldapContextFactory
     * factory used to retrieve LDAP connections.
     * @return an [AuthorizationInfo] instance containing information
     * retrieved from the LDAP server.
     * @throws NamingException
     * if any LDAP errors occur during the search.
     */
    @Throws(NamingException::class)
    public override fun queryForAuthorizationInfo(principals: PrincipalCollection?,
                                                  ldapContextFactory: LdapContextFactory?): AuthorizationInfo? {
        if (!isAuthorizationEnabled) {
            return null
        }
        val roleNames = getRoles(principals, ldapContextFactory!!)
        if (log.isDebugEnabled) {
            log.debug("RolesNames Authorization: $roleNames")
        }
        val simpleAuthorizationInfo = SimpleAuthorizationInfo(roleNames)
        val stringPermissions = permsFor(roleNames)
        simpleAuthorizationInfo.stringPermissions = stringPermissions
        return simpleAuthorizationInfo
    }

    @Throws(NamingException::class)
    private fun hasAllowedAuthenticationRules(principals: PrincipalCollection,
                                              ldapContextFactory: LdapContextFactory): Boolean {
        var allowed = allowedRolesForAuthentication.isEmpty()
        if (!allowed) {
            val roles = getRoles(principals, ldapContextFactory)
            for (allowedRole in allowedRolesForAuthentication) {
                if (roles.contains(allowedRole)) {
                    log.debug("Allowed role for user [$allowedRole] found.")
                    allowed = true
                    break
                }
            }
        }
        return allowed
    }

    @Throws(NamingException::class)
    private fun getRoles(principals: PrincipalCollection?,
                         ldapContextFactory: LdapContextFactory): Set<String> {
        val username = getAvailablePrincipal(principals) as String

        var systemLdapCtx: LdapContext? = null
        try {
            systemLdapCtx = ldapContextFactory.systemLdapContext
            return rolesFor(principals, username, systemLdapCtx,
                    ldapContextFactory, SecurityUtils.getSubject().session)
        } catch (ae: AuthenticationException) {
            ae.printStackTrace()
            return emptySet()
        } finally {
            LdapUtils.closeContext(systemLdapCtx)
        }
    }

    @Throws(NamingException::class)
    fun rolesFor(principals: PrincipalCollection?, userNameIn: String,
                 ldapCtx: LdapContext?, ldapContextFactory: LdapContextFactory, session: Session): Set<String> {
        val roleNames = HashSet<String>()
        val groupNames = HashSet<String>()
        val userName: String
        if (userLowerCase) {
            log.debug("userLowerCase true")
            userName = userNameIn.toLowerCase()
        } else {
            userName = userNameIn
        }

        val userDn = getUserDnForSearch(userName)

        // Activate paged results
        val pageSize = pagingSize
        if (log.isDebugEnabled) {
            log.debug("Ldap PagingSize: $pageSize")
        }
        var numResults = 0
        val cookie: ByteArray? = null
        try {
            ldapCtx!!.addToEnvironment(Context.REFERRAL, "ignore")

            ldapCtx.requestControls = arrayOf<Control>(PagedResultsControl(pageSize,
                    Control.NONCRITICAL))

            do {
                // ldapsearch -h localhost -p 33389 -D
                // uid=guest,ou=people,dc=hadoop,dc=apache,dc=org -w guest-password
                // -b dc=hadoop,dc=apache,dc=org -s sub '(objectclass=*)'
                var searchResultEnum: NamingEnumeration<SearchResult>? = null
                val searchControls = groupSearchControls
                try {
                    if (isGroupSearchEnableMatchingRuleInChain) {
                        searchResultEnum = ldapCtx.search(
                                groupSearchBase,
                                String.format(
                                        MATCHING_RULE_IN_CHAIN_FORMAT, groupObjectClass, memberAttribute, userDn),
                                searchControls)
                        while (searchResultEnum != null && searchResultEnum.hasMore()) {
                            // searchResults contains all the groups in search scope
                            numResults++
                            val group = searchResultEnum.next()

                            val attribute = group.attributes.get(groupIdAttribute)
                            val groupName = attribute.get().toString()

                            val roleName = roleNameFor(groupName)
                            if (roleName != null) {
                                roleNames.add(roleName)
                            } else {
                                roleNames.add(groupName)
                            }
                        }
                    } else {
                        // Default group search filter
                        var searchFilter = String.format("(objectclass=%1\$s)", groupObjectClass)

                        // If group search filter is defined in Shiro config, then use it
                        if (this.groupSearchFilter != null) {
                            searchFilter = expandTemplate(this.groupSearchFilter!!, userName)
                            //searchFilter = String.format("%1$s", groupSearchFilter);
                        }
                        if (log.isDebugEnabled) {
                            log.debug("Group SearchBase|SearchFilter|GroupSearchScope: " + groupSearchBase
                                    + "|" + searchFilter + "|" + this.groupSearchScope)
                        }
                        searchResultEnum = ldapCtx.search(
                                groupSearchBase,
                                searchFilter,
                                searchControls)
                        while (searchResultEnum != null && searchResultEnum.hasMore()) {
                            // searchResults contains all the groups in search scope
                            numResults++
                            val group = searchResultEnum.next()
                            addRoleIfMember(userDn, group, roleNames, groupNames, ldapContextFactory)
                        }
                    }
                } catch (e: PartialResultException) {
                    log.debug("Ignoring PartitalResultException")
                } finally {
                    if (searchResultEnum != null) {
                        searchResultEnum.close()
                    }
                }
                // Re-activate paged results
                ldapCtx.requestControls = arrayOf<Control>(PagedResultsControl(pageSize,
                        cookie, Control.CRITICAL))
            } while (cookie != null)
        } catch (e: SizeLimitExceededException) {
            log.info("Only retrieved first " + numResults +
                    " groups due to SizeLimitExceededException.")
        } catch (e: IOException) {
            log.error("Unabled to setup paged results")
        }

        // save role names and group names in session so that they can be
        // easily looked up outside of this object
        session.setAttribute(SUBJECT_USER_ROLES, roleNames)
        session.setAttribute(SUBJECT_USER_GROUPS, groupNames)
        if (!groupNames.isEmpty() && principals is MutablePrincipalCollection) {
            principals.addAll(groupNames, name)
        }
        if (log.isDebugEnabled) {
            log.debug("User RoleNames: $userName::$roleNames")
        }
        return roleNames
    }

    fun getUserDnForSearch(userName: String): String {
        return if (this.userSearchAttributeName == null || this.userSearchAttributeName!!.isEmpty()) {
            // memberAttributeValuePrefix and memberAttributeValueSuffix
            // were computed from memberAttributeValueTemplate
            memberDn(userName)
        } else {
            getUserDn(userName)
        }
    }

    @Throws(NamingException::class)
    private fun addRoleIfMember(userDn: String, group: SearchResult,
                                roleNames: MutableSet<String>, groupNames: MutableSet<String>,
                                ldapContextFactory: LdapContextFactory) {
        var attributeEnum: NamingEnumeration<out Attribute>? = null
        var ne: NamingEnumeration<*>? = null
        try {
            val userLdapDn = LdapName(userDn)
            val attribute = group.attributes.get(groupIdAttribute)
            val groupName = attribute.get().toString()

            attributeEnum = group.attributes.all
            while (attributeEnum!!.hasMore()) {
                val attr = attributeEnum.next()
                if (!memberAttribute.equals(attr.id, ignoreCase = true)) {
                    continue
                }
                ne = attr.all
                while (ne!!.hasMore()) {
                    var attrValue = ne.next().toString()
                    if (memberAttribute.equals(MEMBER_URL, ignoreCase = true)) {
                        val dynamicGroupMember = isUserMemberOfDynamicGroup(userLdapDn, attrValue,
                                ldapContextFactory)
                        if (dynamicGroupMember) {
                            groupNames.add(groupName)
                            val roleName = roleNameFor(groupName)
                            if (roleName != null) {
                                roleNames.add(roleName)
                            } else {
                                roleNames.add(groupName)
                            }
                        }
                    } else {
                        // posix groups' members don' include the entire dn
                        if (groupObjectClass.equals(POSIX_GROUP, ignoreCase = true)) {
                            attrValue = memberDn(attrValue)
                        }
                        if (userLdapDn == LdapName(attrValue)) {
                            groupNames.add(groupName)
                            val roleName = roleNameFor(groupName)
                            if (roleName != null) {
                                roleNames.add(roleName)
                            } else {
                                roleNames.add(groupName)
                            }
                            break
                        }
                    }
                }
            }
        } finally {
            try {
                if (attributeEnum != null) {
                    attributeEnum.close()
                }
            } finally {
                if (ne != null) {
                    ne.close()
                }
            }
        }
    }

    private fun memberDn(attrValue: String): String {
        return memberAttributeValuePrefix + attrValue + memberAttributeValueSuffix
    }

    private fun roleNameFor(groupName: String): String? {
        return if (!rolesByGroup.isEmpty()) rolesByGroup[groupName] else groupName
    }

    private fun permsFor(roleNames: Set<String>): Set<String> {
        val perms = LinkedHashSet<String>() // preserve order
        for (role in roleNames) {
            val permsForRole = permissionsByRole[role]
            if (log.isDebugEnabled) {
                log.debug("PermsForRole: $role")
                log.debug("PermByRole: " + permsForRole!!)
            }
            if (permsForRole != null) {
                perms.addAll(permsForRole)
            }
        }
        return perms
    }

    /**
     * Set Member Attribute Template for LDAP.
     *
     * @param template
     * DN template to be used to query ldap.
     * @throws IllegalArgumentException
     * if template is empty or null.
     */
    fun setMemberAttributeValueTemplate(template: String) {
        if (!StringUtils.hasText(template)) {
            val msg = "User DN template cannot be null or empty."
            throw IllegalArgumentException(msg)
        }
        val index = template.indexOf(MEMBER_SUBSTITUTION_TOKEN)
        if (index < 0) {
            val msg = ("Member attribute value template must contain the '" + MEMBER_SUBSTITUTION_TOKEN
                    + "' replacement token to understand how to " + "parse the group members.")
            throw IllegalArgumentException(msg)
        }
        val prefix = template.substring(0, index)
        val suffix = template.substring(prefix.length + MEMBER_SUBSTITUTION_TOKEN.length)
        this.memberAttributeValuePrefix = prefix
        this.memberAttributeValueSuffix = suffix
    }

    fun setAllowedRolesForAuthentication(allowedRolesForAuthencation: List<String>) {
        this.allowedRolesForAuthentication.addAll(allowedRolesForAuthencation)
    }

    fun setRolesByGroup(rolesByGroup: Map<String, String>) {
        this.rolesByGroup.putAll(rolesByGroup)
    }

    fun getRolesByGroup(): Map<String, String> {
        return rolesByGroup
    }

    fun setPermissionsByRole(permissionsByRoleStr: String) {
        permissionsByRole.putAll(parsePermissionByRoleString(permissionsByRoleStr))
    }

    fun getPermissionsByRole(): Map<String, List<String>> {
        return permissionsByRole
    }

    private fun parsePermissionByRoleString(permissionsByRoleStr: String): Map<String, List<String>> {
        val perms = HashMap<String, List<String>>()

        // split by semicolon ; then by eq = then by comma ,
        val stSem = StringTokenizer(permissionsByRoleStr, ";")
        while (stSem.hasMoreTokens()) {
            val roleAndPerm = stSem.nextToken()
            val stEq = StringTokenizer(roleAndPerm, "=")
            if (stEq.countTokens() != 2) {
                continue
            }
            val role = stEq.nextToken().trim { it <= ' ' }
            val perm = stEq.nextToken().trim { it <= ' ' }
            val stCom = StringTokenizer(perm, ",")
            val permList = ArrayList<String>()
            while (stCom.hasMoreTokens()) {
                permList.add(stCom.nextToken().trim { it <= ' ' })
            }
            perms[role] = permList
        }
        return perms
    }

    @Throws(NamingException::class)
    internal fun isUserMemberOfDynamicGroup(userLdapDn: LdapName, memberUrl: String?,
                                            ldapContextFactory: LdapContextFactory): Boolean {
        // ldap://host:port/dn?attributes?scope?filter?extensions
        if (memberUrl == null) {
            return false
        }
        val tokens = memberUrl.split("\\?".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        if (tokens.size < 4) {
            return false
        }

        val searchBaseString = tokens[0].substring(tokens[0].lastIndexOf("/") + 1)
        val searchScope = tokens[2]
        val searchFilter = tokens[3]

        val searchBaseDn = LdapName(searchBaseString)

        // do scope test
        if (searchScope.equals("base", ignoreCase = true)) {
            log.debug("DynamicGroup SearchScope base")
            return false
        }
        if (!userLdapDn.toString().endsWith(searchBaseDn.toString())) {
            return false
        }
        if (searchScope.equals("one", ignoreCase = true) && userLdapDn.size() != searchBaseDn.size() - 1) {
            log.debug("DynamicGroup SearchScope one")
            return false
        }
        // search for the filter, substituting base with userDn
        // search for base_dn=userDn, scope=base, filter=filter
        var systemLdapCtx: LdapContext? = null
        systemLdapCtx = ldapContextFactory.systemLdapContext
        val member = false
        var searchResultEnum: NamingEnumeration<SearchResult>? = null
        try {
            searchResultEnum = systemLdapCtx!!.search(userLdapDn, searchFilter,
                    if (searchScope.equals("sub", ignoreCase = true)) SUBTREE_SCOPE else ONELEVEL_SCOPE)
            if (searchResultEnum!!.hasMore()) {
                return true
            }
        } finally {
            try {
                if (searchResultEnum != null) {
                    searchResultEnum.close()
                }
            } finally {
                LdapUtils.closeContext(systemLdapCtx)
            }
        }
        return member
    }

    @Throws(IllegalArgumentException::class)
    override fun setUserDnTemplate(template: String) {
        userDnTemplate = template
    }

    private fun matchPrincipal(principal: String): String {
        val matchedPrincipal = principalPattern.matcher(principal)
        if (!matchedPrincipal.matches()) {
            throw IllegalArgumentException("Principal "
                    + principal + " does not match " + this.principalRegex)
        }
        return matchedPrincipal.group()
    }

    /**
     * Returns the LDAP User Distinguished Name (DN) to use when acquiring an
     * [LdapContext][javax.naming.ldap.LdapContext] from the
     * [LdapContextFactory].
     *
     *
     * If the the [userDnTemplate][.getUserDnTemplate] property has been
     * set, this implementation will construct the User DN by substituting the
     * specified `principal` into the configured template. If the
     * [userDnTemplate][.getUserDnTemplate] has not been set, the method
     * argument will be returned directly (indicating that the submitted
     * authentication token principal *is* the User DN).
     *
     * @param principal
     * the principal to substitute into the configured
     * [userDnTemplate][.getUserDnTemplate].
     * @return the constructed User DN to use at runtime when acquiring an
     * [javax.naming.ldap.LdapContext].
     * @throws IllegalArgumentException
     * if the method argument is null or empty
     * @throws IllegalStateException
     * if the [userDnTemplate][.getUserDnTemplate] has not been
     * set.
     * @see LdapContextFactory.getLdapContext
     */
    @Throws(IllegalArgumentException::class, IllegalStateException::class)
    public override fun getUserDn(principal: String): String {
        val userDn: String
        val matchedPrincipal = matchPrincipal(principal)
        val userSearchBase = userSearchBase
        val userSearchAttributeName = userSearchAttributeName

        // If not searching use the userDnTemplate and return.
        if (userSearchBase == null || userSearchBase.isEmpty() || (userSearchAttributeName == null
                        && this.userSearchFilter == null && !"object".equals(this.userSearchScope!!, ignoreCase = true))) {
            userDn = expandTemplate(userDnTemplate, matchedPrincipal)
            if (log.isDebugEnabled) {
                log.debug("LDAP UserDN and Principal: $userDn,$principal")
            }
            return userDn
        }

        // Create the searchBase and searchFilter from config.
        val searchBase = expandTemplate(userSearchBase, matchedPrincipal)
        var searchFilter: String? = null
        if (this.userSearchFilter == null) {
            if (userSearchAttributeName == null) {
                searchFilter = String.format("(objectclass=%1\$s)", userObjectClass)
            } else {
                searchFilter = String.format("(&(objectclass=%1\$s)(%2\$s=%3\$s))", userObjectClass,
                        userSearchAttributeName, expandTemplate(userSearchAttributeTemplate!!,
                        matchedPrincipal))
            }
        } else {
            searchFilter = expandTemplate(this.userSearchFilter!!, matchedPrincipal)
        }
        val searchControls = userSearchControls

        // Search for userDn and return.
        var systemLdapCtx: LdapContext? = null
        var searchResultEnum: NamingEnumeration<SearchResult>? = null
        try {
            systemLdapCtx = contextFactory.systemLdapContext
            if (log.isDebugEnabled) {
                log.debug("SearchBase,SearchFilter,UserSearchScope: " + searchBase
                        + "," + searchFilter + "," + this.userSearchScope)
            }
            searchResultEnum = systemLdapCtx!!.search(searchBase, searchFilter, searchControls)
            // SearchResults contains all the entries in search scope
            if (searchResultEnum!!.hasMore()) {
                val searchResult = searchResultEnum.next()
                userDn = searchResult.nameInNamespace
                if (log.isDebugEnabled) {
                    log.debug("UserDN Returned,Principal: $userDn,$principal")
                }
                return userDn
            } else {
                throw IllegalArgumentException("Illegal principal name: $principal")
            }
        } catch (ne: AuthenticationException) {
            ne.printStackTrace()
            throw IllegalArgumentException("Illegal principal name: $principal")
        } catch (ne: NamingException) {
            throw IllegalArgumentException("Hit NamingException: " + ne.message)
        } finally {
            try {
                if (searchResultEnum != null) {
                    searchResultEnum.close()
                }
            } catch (ne: NamingException) {
                // Ignore exception on close.
            } finally {
                LdapUtils.closeContext(systemLdapCtx)
            }
        }
    }

    @Throws(NamingException::class)
    override fun createAuthenticationInfo(token: AuthenticationToken,
                                          ldapPrincipal: Any?, ldapCredentials: Any?, ldapContext: LdapContext?): AuthenticationInfo {
        val builder = HashRequest.Builder()
        val credentialsHash = hashService
                .computeHash(builder.setSource(token.credentials)
                        .setAlgorithmName(HASHING_ALGORITHM).build())
        return SimpleAuthenticationInfo(token.principal,
                credentialsHash.toHex(), credentialsHash.salt,
                name)
    }

    companion object {

        private val SUBTREE_SCOPE = SearchControls()
        private val ONELEVEL_SCOPE = SearchControls()
        private val OBJECT_SCOPE = SearchControls()
        private val SUBJECT_USER_ROLES = "subject.userRoles"
        private val SUBJECT_USER_GROUPS = "subject.userGroups"
        private val MEMBER_URL = "memberUrl"
        private val POSIX_GROUP = "posixGroup"

        // LDAP Operator '1.2.840.113556.1.4.1941'
        // walks the chain of ancestry in objects all the way to the root until it finds a match
        // see https://msdn.microsoft.com/en-us/library/aa746475(v=vs.85).aspx
        private val MATCHING_RULE_IN_CHAIN_FORMAT = "(&(objectClass=%s)(%s:1.2.840.113556.1.4.1941:=%s))"

        private val TEMPLATE_PATTERN = Pattern.compile("\\{(\\d+?)\\}")
        private val DEFAULT_PRINCIPAL_REGEX = "(.*)"
        private val MEMBER_SUBSTITUTION_TOKEN = "{0}"
        private val HASHING_ALGORITHM = "SHA-1"
        private val log = LoggerFactory.getLogger(LdapRealm::class.java)

        init {
            SUBTREE_SCOPE.searchScope = SearchControls.SUBTREE_SCOPE
            ONELEVEL_SCOPE.searchScope = SearchControls.ONELEVEL_SCOPE
            OBJECT_SCOPE.searchScope = SearchControls.OBJECT_SCOPE
        }

        internal fun getSystemPassword(hadoopSecurityCredentialPath: String,
                                       keystorePass: String): String {
            var password = ""
            try {
                val configuration = Configuration()
                configuration.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH,
                        hadoopSecurityCredentialPath)
                val provider = CredentialProviderFactory.getProviders(configuration)[0]
                val credEntry = provider.getCredentialEntry(keystorePass)
                if (credEntry != null) {
                    password = String(credEntry.credential)
                }
            } catch (e: IOException) {
                throw ShiroException("Error from getting credential entry from keystore", e)
            }

            if (org.apache.commons.lang.StringUtils.isEmpty(password)) {
                throw ShiroException("Error getting SystemPassword from the provided keystore:"
                        + keystorePass + ", in path:" + hadoopSecurityCredentialPath)
            }
            return password
        }

        fun expandTemplate(template: String, input: String): String {
            return template.replace(MEMBER_SUBSTITUTION_TOKEN, input)
        }
    }
}

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
package org.apache.zeppelin.rest

import org.apache.commons.lang3.StringUtils
import org.apache.commons.lang3.reflect.FieldUtils
import org.apache.shiro.realm.jdbc.JdbcRealm
import org.apache.shiro.realm.ldap.JndiLdapContextFactory
import org.apache.shiro.realm.ldap.JndiLdapRealm
import org.apache.shiro.realm.text.IniRealm
import org.apache.shiro.util.JdbcUtils
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.sql.Connection
import java.sql.PreparedStatement
import java.sql.ResultSet
import java.util.ArrayList

import javax.naming.NamingEnumeration
import javax.naming.directory.Attributes
import javax.naming.directory.SearchControls
import javax.naming.directory.SearchResult
import javax.naming.ldap.LdapContext
import javax.sql.DataSource

import org.apache.zeppelin.realm.ActiveDirectoryGroupRealm
import org.apache.zeppelin.realm.LdapRealm

/**
 * This is class which help fetching users from different realms.
 * getUserList() function is overloaded and according to the realm passed to the function it
 * extracts users from its respective realm
 */
class GetUserList {

    /**
     * Function to extract users from shiro.ini.
     */
    fun getUserList(r: IniRealm): List<String> {
        val userList = ArrayList<String>()
        val getIniUser = r.ini["users"]
        if (getIniUser != null) {
            val it = getIniUser.entries.iterator()
            while (it.hasNext()) {
                val pair = it.next()
                userList.add(pair.key.toString().trim({ it <= ' ' }))
            }
        }
        return userList
    }


    /***
     * Get user roles from shiro.ini.
     *
     * @param r
     * @return
     */
    fun getRolesList(r: IniRealm): List<String> {
        val roleList = ArrayList<String>()
        val getIniRoles = r.ini["roles"]
        if (getIniRoles != null) {
            val it = getIniRoles.entries.iterator()
            while (it.hasNext()) {
                val pair = it.next()
                roleList.add(pair.key.toString().trim({ it <= ' ' }))
            }
        }
        return roleList
    }

    /**
     * Function to extract users from LDAP.
     */
    fun getUserList(r: JndiLdapRealm, searchText: String, numUsersToFetch: Int): List<String> {
        val userList = ArrayList<String>()
        val userDnTemplate = r.userDnTemplate
        val userDn = userDnTemplate.split(",".toRegex(), 2).toTypedArray()
        val userDnPrefix = userDn[0].split("=".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()[0]
        val userDnSuffix = userDn[1]
        val cf = r.contextFactory as JndiLdapContextFactory
        try {
            val ctx = cf.systemLdapContext
            val constraints = SearchControls()
            constraints.countLimit = numUsersToFetch.toLong()
            constraints.searchScope = SearchControls.SUBTREE_SCOPE
            val attrIDs = arrayOf(userDnPrefix)
            constraints.returningAttributes = attrIDs
            val result = ctx.search(userDnSuffix, "(" + userDnPrefix + "=*" + searchText +
                    "*)", constraints)
            while (result.hasMore()) {
                val attrs = (result.next() as SearchResult).attributes
                if (attrs.get(userDnPrefix) != null) {
                    val currentUser = attrs.get(userDnPrefix).toString()
                    userList.add(currentUser.split(":".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()[1].trim { it <= ' ' })
                }
            }
        } catch (e: Exception) {
            LOG.error("Error retrieving User list from Ldap Realm", e)
        }

        LOG.info("UserList: $userList")
        return userList
    }

    /**
     * Function to extract users from Zeppelin LdapRealm.
     */
    fun getUserList(r: LdapRealm, searchText: String, numUsersToFetch: Int): List<String> {
        val userList = ArrayList<String>()
        if (LOG.isDebugEnabled) {
            LOG.debug("SearchText: $searchText")
        }
        val userAttribute = r.userSearchAttributeName
        val userSearchRealm = r.userSearchBase
        val userObjectClass = r.userObjectClass
        val cf = r.contextFactory as JndiLdapContextFactory
        try {
            val ctx = cf.systemLdapContext
            val constraints = SearchControls()
            constraints.searchScope = SearchControls.SUBTREE_SCOPE
            constraints.countLimit = numUsersToFetch.toLong()
            val attrIDs = arrayOf<String>(userAttribute!!)
            constraints.returningAttributes = attrIDs
            val result = ctx.search(userSearchRealm, "(&(objectclass=" +
                    userObjectClass + ")("
                    + userAttribute + "=*" + searchText + "*))", constraints)
            while (result.hasMore()) {
                val attrs = (result.next() as SearchResult).attributes
                if (attrs.get(userAttribute) != null) {
                    val currentUser: String
                    if (r.userLowerCase) {
                        LOG.debug("userLowerCase true")
                        currentUser = (attrs.get(userAttribute).get() as String).toLowerCase()
                    } else {
                        LOG.debug("userLowerCase false")
                        currentUser = attrs.get(userAttribute).get() as String
                    }
                    if (LOG.isDebugEnabled) {
                        LOG.debug("CurrentUser: $currentUser")
                    }
                    userList.add(currentUser.trim { it <= ' ' })
                }
            }
        } catch (e: Exception) {
            LOG.error("Error retrieving User list from Ldap Realm", e)
        }

        return userList
    }

    /***
     * Get user roles from shiro.ini for Zeppelin LdapRealm.
     *
     * @param r
     * @return
     */
    fun getRolesList(r: LdapRealm): List<String> {
        val roleList = ArrayList<String>()
        val roles = r.listRoles
        if (roles != null) {
            val it = roles.entries.iterator()
            while (it.hasNext()) {
                val pair = it.next()
                if (LOG.isDebugEnabled) {
                    LOG.debug("RoleKeyValue: " + pair.key +
                            " = " + pair.value)
                }
                roleList.add(pair.key as String)
            }
        }
        return roleList
    }

    fun getUserList(r: ActiveDirectoryGroupRealm, searchText: String,
                    numUsersToFetch: Int): List<String> {
        var userList: List<String> = ArrayList()
        try {
            val ctx = r.getLdapContextFactory().systemLdapContext
            userList = r.searchForUserName(searchText, ctx, numUsersToFetch)
        } catch (e: Exception) {
            LOG.error("Error retrieving User list from ActiveDirectory Realm", e)
        }

        return userList
    }

    /**
     * Function to extract users from JDBCs.
     */
    fun getUserList(obj: JdbcRealm): List<String>? {
        val userlist = ArrayList<String>()
        var con: Connection? = null
        var ps: PreparedStatement? = null
        var rs: ResultSet? = null
        var dataSource: DataSource? = null
        var authQuery = ""
        var retval: Array<String>
        var tablename = ""
        var username = ""
        val userquery: String
        try {
            dataSource = FieldUtils.readField(obj, "dataSource", true) as DataSource
            authQuery = FieldUtils.readField(obj, "authenticationQuery", true) as String
            LOG.info(authQuery)
            val authQueryLowerCase = authQuery.toLowerCase()
            retval = authQueryLowerCase.split("from".toRegex(), 2).toTypedArray()
            if (retval.size >= 2) {
                retval = retval[1].split("with|where".toRegex(), 2).toTypedArray()
                tablename = retval[0]
                retval = retval[1].split("where".toRegex(), 2).toTypedArray()
                if (retval.size >= 2) {
                    retval = retval[1].split("=".toRegex(), 2).toTypedArray()
                } else {
                    retval = retval[0].split("=".toRegex(), 2).toTypedArray()
                }
                username = retval[0]
            }

            if (StringUtils.isBlank(username) || StringUtils.isBlank(tablename)) {
                return userlist
            }

            userquery = String.format("SELECT %s FROM %s", username, tablename)
        } catch (e: IllegalAccessException) {
            LOG.error("Error while accessing dataSource for JDBC Realm", e)
            return null
        }

        try {
            con = dataSource.connection
            ps = con!!.prepareStatement(userquery)
            rs = ps!!.executeQuery()
            while (rs!!.next()) {
                userlist.add(rs.getString(1).trim { it <= ' ' })
            }
        } catch (e: Exception) {
            LOG.error("Error retrieving User list from JDBC Realm", e)
        } finally {
            JdbcUtils.closeResultSet(rs)
            JdbcUtils.closeStatement(ps)
            JdbcUtils.closeConnection(con)
        }
        return userlist
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(GetUserList::class.java)
    }
}

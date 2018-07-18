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

import com.google.gson.Gson
import org.apache.commons.lang3.StringUtils
import org.apache.shiro.realm.Realm
import org.apache.shiro.realm.jdbc.JdbcRealm
import org.apache.shiro.realm.ldap.JndiLdapRealm
import org.apache.shiro.realm.text.IniRealm
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.util.ArrayList
import java.util.Collections
import java.util.Comparator
import java.util.HashMap
import java.util.HashSet

import javax.ws.rs.GET
import javax.ws.rs.Path
import javax.ws.rs.PathParam
import javax.ws.rs.Produces
import javax.ws.rs.core.Response

import org.apache.zeppelin.annotation.ZeppelinApi
import org.apache.zeppelin.conf.ZeppelinConfiguration
import org.apache.zeppelin.realm.ActiveDirectoryGroupRealm
import org.apache.zeppelin.realm.LdapRealm
import org.apache.zeppelin.server.JsonResponse
import org.apache.zeppelin.ticket.TicketContainer
import org.apache.zeppelin.utils.SecurityUtils

/**
 * Zeppelin security rest api endpoint.
 */
/**
 * Required by Swagger.
 */
@Path("/security")
@Produces("application/json")
class SecurityRestApi {

    /**
     * Get ticket
     * Returns username & ticket
     * for anonymous access, username is always anonymous.
     * After getting this ticket, access through websockets become safe
     *
     * @return 200 response
     */
    @GET
    @Path("ticket")
    @ZeppelinApi
    fun ticket(): Response {
        val conf = ZeppelinConfiguration.create()
        val principal = SecurityUtils.principal
        val roles = SecurityUtils.roles
        val response: JsonResponse<*>
        // ticket set to anonymous for anonymous user. Simplify testing.
        val ticket: String
        if ("anonymous" == principal) {
            ticket = "anonymous"
        } else {
            ticket = TicketContainer.instance.getTicket(principal)
        }

        val data = HashMap<String, String>()
        data["principal"] = principal
        data["roles"] = gson.toJson(roles)
        data["ticket"] = ticket

        response = JsonResponse(Response.Status.OK, "", data)
        LOG.warn(response.toString())
        return response.build()
    }

    /**
     * Get userlist.
     *
     * Returns list of all user from available realms
     *
     * @return 200 response
     */
    @GET
    @Path("userlist/{searchText}")
    fun getUserList(@PathParam("searchText") searchText: String): Response {

        val numUsersToFetch = 5
        val usersList = ArrayList<String>()
        val rolesList = ArrayList<String>()
        try {
            val getUserListObj = GetUserList()
            val realmsList = SecurityUtils.realmsList
            if (realmsList != null) {
                val iterator = realmsList.iterator()
                while (iterator.hasNext()) {
                    val realm = iterator.next()
                    val name = realm!!.javaClass.getName()
                    if (LOG.isDebugEnabled) {
                        LOG.debug("RealmClass.getName: $name")
                    }
                    if (name == "org.apache.shiro.realm.text.IniRealm") {
                        usersList.addAll(getUserListObj.getUserList(realm as IniRealm))
                        rolesList.addAll(getUserListObj.getRolesList(realm))
                    } else if (name == "org.apache.zeppelin.realm.LdapGroupRealm") {
                        usersList.addAll(getUserListObj.getUserList(realm as JndiLdapRealm, searchText,
                                numUsersToFetch))
                    } else if (name == "org.apache.zeppelin.realm.LdapRealm") {
                        usersList.addAll(getUserListObj.getUserList(realm as LdapRealm, searchText,
                                numUsersToFetch))
                        rolesList.addAll(getUserListObj.getRolesList(realm))
                    } else if (name == "org.apache.zeppelin.realm.ActiveDirectoryGroupRealm") {
                        usersList.addAll(getUserListObj.getUserList(realm as ActiveDirectoryGroupRealm,
                                searchText, numUsersToFetch))
                    } else if (name == "org.apache.shiro.realm.jdbc.JdbcRealm") {
                        usersList.addAll(getUserListObj.getUserList(realm as JdbcRealm)!!)
                    }
                }
            }
        } catch (e: Exception) {
            LOG.error("Exception in retrieving Users from realms ", e)
        }

        val autoSuggestUserList = ArrayList<String>()
        val autoSuggestRoleList = ArrayList<String>()
        Collections.sort(usersList)
        Collections.sort(rolesList)
        Collections.sort(usersList, Comparator { o1, o2 ->
            if (o1.matches("$searchText(.*)".toRegex()) && o2.matches("$searchText(.*)".toRegex())) {
                return@Comparator 0
            } else if (o1.matches("$searchText(.*)".toRegex())) {
                return@Comparator -1
            }
            0
        })
        var maxLength = 0
        for (user in usersList) {
            if (StringUtils.containsIgnoreCase(user, searchText)) {
                autoSuggestUserList.add(user)
                maxLength++
            }
            if (maxLength == numUsersToFetch) {
                break
            }
        }

        for (role in rolesList) {
            if (StringUtils.containsIgnoreCase(role, searchText)) {
                autoSuggestRoleList.add(role)
            }
        }

        val returnListMap = HashMap<String, List<*>>()
        returnListMap["users"] = autoSuggestUserList
        returnListMap["roles"] = autoSuggestRoleList

        return JsonResponse<Map<String, List<*>>>(Response.Status.OK, "", returnListMap).build()
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(SecurityRestApi::class.java)
        private val gson = Gson()
    }
}

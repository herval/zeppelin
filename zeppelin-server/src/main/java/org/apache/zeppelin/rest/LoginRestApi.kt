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
import org.apache.shiro.authc.AuthenticationException
import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.authc.IncorrectCredentialsException
import org.apache.shiro.authc.LockedAccountException
import org.apache.shiro.authc.UnknownAccountException
import org.apache.shiro.authc.UsernamePasswordToken
import org.apache.shiro.realm.Realm
import org.apache.shiro.subject.Subject
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.text.ParseException
import java.util.HashMap
import java.util.HashSet

import javax.ws.rs.FormParam
import javax.ws.rs.GET
import javax.ws.rs.POST
import javax.ws.rs.Path
import javax.ws.rs.Produces
import javax.ws.rs.core.Context
import javax.ws.rs.core.Cookie
import javax.ws.rs.core.HttpHeaders
import javax.ws.rs.core.Response
import javax.ws.rs.core.Response.Status

import org.apache.zeppelin.annotation.ZeppelinApi
import org.apache.zeppelin.notebook.NotebookAuthorization
import org.apache.zeppelin.realm.jwt.JWTAuthenticationToken
import org.apache.zeppelin.realm.jwt.KnoxJwtRealm
import org.apache.zeppelin.server.JsonResponse
import org.apache.zeppelin.ticket.TicketContainer
import org.apache.zeppelin.utils.SecurityUtils

/**
 * Created for org.apache.zeppelin.rest.message.
 */
/**
 * Required by Swagger.
 */
@Path("/login")
@Produces("application/json")
class LoginRestApi {

    private val jtwRealm: KnoxJwtRealm?
        get() {
            val realmsList = SecurityUtils.getRealmsList()
            if (realmsList != null) {
                val iterator = realmsList.iterator()
                while (iterator.hasNext()) {
                    val realm = iterator.next()
                    val name = realm.javaClass.getName()

                    LOG.debug("RealmClass.getName: $name")

                    if (name == "org.apache.zeppelin.realm.jwt.KnoxJwtRealm") {
                        return realm as KnoxJwtRealm
                    }
                }
            }
            return null
        }

    private val isKnoxSSOEnabled: Boolean
        get() {
            val realmsList = SecurityUtils.getRealmsList()
            if (realmsList != null) {
                val iterator = realmsList.iterator()
                while (iterator.hasNext()) {
                    val realm = iterator.next()
                    val name = realm.javaClass.getName()
                    LOG.debug("RealmClass.getName: $name")
                    if (name == "org.apache.zeppelin.realm.jwt.KnoxJwtRealm") {
                        return true
                    }
                }
            }
            return false
        }

    @GET
    @ZeppelinApi
    fun getLogin(@Context headers: HttpHeaders): Response {
        var response: JsonResponse<*>? = null
        if (isKnoxSSOEnabled) {
            val knoxJwtRealm = jtwRealm
            val cookie = headers.cookies[knoxJwtRealm!!.cookieName]
            if (cookie != null && cookie.value != null) {
                val currentUser = org.apache.shiro.SecurityUtils.getSubject()
                val token = JWTAuthenticationToken(null, cookie.value)
                try {
                    val name = knoxJwtRealm.getName(token)
                    if (!currentUser.isAuthenticated || currentUser.principal != name) {
                        response = proceedToLogin(currentUser, token)
                    }
                } catch (e: ParseException) {
                    LOG.error("ParseException in LoginRestApi: ", e)
                }

            }
            if (response == null) {
                val data = HashMap<String, String>()
                data["redirectURL"] = constructKnoxUrl(knoxJwtRealm, knoxJwtRealm.login)
                response = JsonResponse(Status.OK, "", data)
            }
            return response.build()
        }
        return JsonResponse(Status.METHOD_NOT_ALLOWED).build()
    }

    private fun proceedToLogin(currentUser: Subject, token: AuthenticationToken): JsonResponse<*>? {
        var response: JsonResponse<*>? = null
        try {
            logoutCurrentUser()
            currentUser.getSession(true)
            currentUser.login(token)

            val roles = SecurityUtils.getRoles()
            val principal = SecurityUtils.getPrincipal()
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
            //if no exception, that's it, we're done!

            //set roles for user in NotebookAuthorization module
            NotebookAuthorization.getInstance().setRoles(principal, roles)
        } catch (uae: UnknownAccountException) {
            //username wasn't in the system, show them an error message?
            LOG.error("Exception in login: ", uae)
        } catch (ice: IncorrectCredentialsException) {
            //password didn't match, try again?
            LOG.error("Exception in login: ", ice)
        } catch (lae: LockedAccountException) {
            //account for that username is locked - can't login.  Show them a message?
            LOG.error("Exception in login: ", lae)
        } catch (ae: AuthenticationException) {
            //unexpected condition - error?
            LOG.error("Exception in login: ", ae)
        }

        return response
    }

    /**
     * Post Login
     * Returns userName & password
     * for anonymous access, username is always anonymous.
     * After getting this ticket, access through websockets become safe
     *
     * @return 200 response
     */
    @POST
    @ZeppelinApi
    fun postLogin(@FormParam("userName") userName: String,
                  @FormParam("password") password: String): Response {
        var response: JsonResponse<*>? = null
        // ticket set to anonymous for anonymous user. Simplify testing.
        val currentUser = org.apache.shiro.SecurityUtils.getSubject()
        if (currentUser.isAuthenticated) {
            currentUser.logout()
        }
        if (!currentUser.isAuthenticated) {

            val token = UsernamePasswordToken(userName, password)

            response = proceedToLogin(currentUser, token)
        }

        if (response == null) {
            response = JsonResponse(Response.Status.FORBIDDEN, "", "")
        }

        LOG.warn(response.toString())
        return response.build()
    }

    @POST
    @Path("logout")
    @ZeppelinApi
    fun logout(): Response {
        val response: JsonResponse<*>
        logoutCurrentUser()
        if (isKnoxSSOEnabled) {
            val knoxJwtRealm = jtwRealm
            val data = HashMap<String, String>()
            data["redirectURL"] = constructKnoxUrl(knoxJwtRealm!!, knoxJwtRealm.logout)
            data["isLogoutAPI"] = knoxJwtRealm.logoutAPI!!.toString()
            response = JsonResponse(Status.UNAUTHORIZED, "", data)
        } else {
            response = JsonResponse(Status.UNAUTHORIZED, "", "")

        }
        LOG.warn(response.toString())
        return response.build()
    }

    private fun constructKnoxUrl(knoxJwtRealm: KnoxJwtRealm, path: String): String {
        val redirectURL = StringBuilder(knoxJwtRealm.providerUrl)
        redirectURL.append(path)
        if (knoxJwtRealm.redirectParam != null) {
            redirectURL.append("?").append(knoxJwtRealm.redirectParam).append("=")
        }
        return redirectURL.toString()
    }

    private fun logoutCurrentUser() {
        val currentUser = org.apache.shiro.SecurityUtils.getSubject()
        TicketContainer.instance.removeTicket(SecurityUtils.getPrincipal())
        currentUser.session.stop()
        currentUser.logout()
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(LoginRestApi::class.java)
        private val gson = Gson()
    }
}

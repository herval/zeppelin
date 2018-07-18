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

import com.google.common.base.Joiner
import com.google.gson.Gson
import com.google.gson.JsonParseException

import org.apache.commons.httpclient.HttpClient
import org.apache.commons.httpclient.HttpStatus
import org.apache.commons.httpclient.methods.PutMethod
import org.apache.commons.httpclient.methods.StringRequestEntity
import org.apache.commons.lang3.StringUtils
import org.apache.shiro.authc.AccountException
import org.apache.shiro.authc.AuthenticationException
import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.authc.SimpleAuthenticationInfo
import org.apache.shiro.authc.UsernamePasswordToken
import org.apache.shiro.authz.AuthorizationInfo
import org.apache.shiro.realm.AuthorizingRealm
import org.apache.shiro.subject.PrincipalCollection
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.io.IOException
import java.net.MalformedURLException
import java.net.URI
import java.net.URISyntaxException
import java.util.HashSet
import java.util.concurrent.atomic.AtomicInteger

import org.apache.zeppelin.common.JsonSerializable
import org.apache.zeppelin.notebook.repo.zeppelinhub.model.UserSessionContainer
import org.apache.zeppelin.notebook.repo.zeppelinhub.websocket.utils.ZeppelinhubUtils
import org.apache.zeppelin.server.ZeppelinServer

/**
 * A `Realm` implementation that uses the ZeppelinHub to authenticate users.
 *
 */
class ZeppelinHubRealm : AuthorizingRealm() {

    private val httpClient: HttpClient

    private var zeppelinhubUrl: String? = null
//    private val name: String

    init {
        LOG.debug("Init ZeppelinhubRealm")
        //TODO(anthonyc): think about more setting for this HTTP client.
        //                eg: if user uses proxy etcetc...
        httpClient = HttpClient()
        name = javaClass.name + "_" + INSTANCE_COUNT.getAndIncrement()
    }

    @Throws(AuthenticationException::class)
    override fun doGetAuthenticationInfo(authToken: AuthenticationToken): AuthenticationInfo {
        val token = authToken as UsernamePasswordToken
        if (StringUtils.isBlank(token.username)) {
            throw AccountException("Empty usernames are not allowed by this realm.")
        }
        val loginPayload = createLoginPayload(token.username, token.password)
        val user = authenticateUser(loginPayload)
        LOG.debug("{} successfully login via ZeppelinHub", user.login)
        return SimpleAuthenticationInfo(user.login, token.password, name)
    }

    override fun doGetAuthorizationInfo(principals: PrincipalCollection): AuthorizationInfo? {
        // TODO(xxx): future work will be done here.
        return null
    }

    override fun onInit() {
        super.onInit()
    }

    /**
     * Setter of ZeppelinHub URL, this will be called by Shiro based on zeppelinhubUrl property
     * in shiro.ini file.
     *
     * It will also perform a check of ZeppelinHub url [.isZeppelinHubUrlValid],
     * if the url is not valid, the default zeppelinhub url will be used.
     *
     * @param url
     */
    fun setZeppelinhubUrl(url: String) {
        if (StringUtils.isBlank(url)) {
            LOG.warn("Zeppelinhub url is empty, setting up default url {}", DEFAULT_ZEPPELINHUB_URL)
            zeppelinhubUrl = DEFAULT_ZEPPELINHUB_URL
        } else {
            zeppelinhubUrl = if (isZeppelinHubUrlValid(url)) url else DEFAULT_ZEPPELINHUB_URL
            LOG.info("Setting up Zeppelinhub url to {}", zeppelinhubUrl)
        }
    }

    /**
     * Send to ZeppelinHub a login request based on the request body which is a JSON that contains 2
     * fields "login" and "password".
     *
     * @param requestBody JSON string of ZeppelinHub payload.
     * @return Account object with login, name (if set in ZeppelinHub), and mail.
     * @throws AuthenticationException if fail to login.
     */
    protected fun authenticateUser(requestBody: String): User {
        val put = PutMethod(Joiner.on("/").join(zeppelinhubUrl, USER_LOGIN_API_ENDPOINT))
        val responseBody: String
        val userSession: String
        try {
            put.requestEntity = StringRequestEntity(requestBody, JSON_CONTENT_TYPE, UTF_8_ENCODING)
            val statusCode = httpClient.executeMethod(put)
            if (statusCode != HttpStatus.SC_OK) {
                LOG.error("Cannot login user, HTTP status code is {} instead on 200 (OK)", statusCode)
                put.releaseConnection()
                throw AuthenticationException("Couldnt login to ZeppelinHub. " + "Login or password incorrect")
            }
            responseBody = put.responseBodyAsString
            userSession = put.getResponseHeader(USER_SESSION_HEADER).value
            put.releaseConnection()

        } catch (e: IOException) {
            LOG.error("Cannot login user", e)
            throw AuthenticationException(e.message)
        }

        val account: User
        try {
            account = User.fromJson(responseBody)
        } catch (e: JsonParseException) {
            LOG.error("Cannot fromJson ZeppelinHub response to User instance", e)
            throw AuthenticationException("Cannot login to ZeppelinHub")
        }

        onLoginSuccess(account.login!!, userSession)

        return account
    }

    /**
     * Create a JSON String that represent login payload.
     *
     * Payload will look like:
     * `{
     * 'login': 'userLogin',
     * 'password': 'userpassword'
     * }
    ` *
     * @param login
     * @param pwd
     * @return
     */
    protected fun createLoginPayload(login: String, pwd: CharArray): String {
        val sb = StringBuilder("{\"login\":\"")
        return sb.append(login).append("\", \"password\":\"").append(pwd).append("\"}").toString()
    }

    /**
     * Perform a Simple URL check by using `URI(url).toURL()`.
     * If the url is not valid, the try-catch condition will catch the exceptions and return false,
     * otherwise true will be returned.
     *
     * @param url
     * @return
     */
    protected fun isZeppelinHubUrlValid(url: String): Boolean {
        var valid: Boolean
        try {
            URI(url).toURL()
            valid = true
        } catch (e: URISyntaxException) {
            LOG.error("Zeppelinhub url is not valid, default ZeppelinHub url will be used.", e)
            valid = false
        } catch (e: MalformedURLException) {
            LOG.error("Zeppelinhub url is not valid, default ZeppelinHub url will be used.", e)
            valid = false
        }

        return valid
    }

    /**
     * Helper class that will be use to fromJson ZeppelinHub response.
     */
    protected class User : JsonSerializable {
        var login: String? = null
        var email: String? = null
        var name: String? = null

        override fun toJson(): String {
            return gson.toJson(this)
        }

        companion object {
            private val gson = Gson()

            fun fromJson(json: String): User {
                return gson.fromJson(json, User::class.java)
            }
        }
    }

    fun onLoginSuccess(username: String, session: String) {
        UserSessionContainer.instance.setSession(username, session)

        /* TODO(xxx): add proper roles */
        val userAndRoles = HashSet<String>()
        userAndRoles.add(username)
        ZeppelinServer.notebookWsServer!!.broadcastReloadedNoteList(
                org.apache.zeppelin.user.AuthenticationInfo(username), userAndRoles)

        ZeppelinhubUtils.userLoginRoutine(username)
    }

    override fun onLogout(principals: PrincipalCollection) {
        ZeppelinhubUtils.userLogoutRoutine(principals.primaryPrincipal as String)
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(ZeppelinHubRealm::class.java)
        private val DEFAULT_ZEPPELINHUB_URL = "https://www.zeppelinhub.com"
        private val USER_LOGIN_API_ENDPOINT = "api/v1/users/login"
        private val JSON_CONTENT_TYPE = "application/json"
        private val UTF_8_ENCODING = "UTF-8"
        private val USER_SESSION_HEADER = "X-session"
        private val INSTANCE_COUNT = AtomicInteger()
    }
}

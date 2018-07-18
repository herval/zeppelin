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

import com.google.common.base.Strings
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.io.IOException

import javax.servlet.http.HttpServletRequest
import javax.ws.rs.DELETE
import javax.ws.rs.GET
import javax.ws.rs.PUT
import javax.ws.rs.Path
import javax.ws.rs.PathParam
import javax.ws.rs.Produces
import javax.ws.rs.core.Context
import javax.ws.rs.core.Response
import javax.ws.rs.core.Response.Status

import org.apache.zeppelin.server.JsonResponse
import org.apache.zeppelin.user.Credentials
import org.apache.zeppelin.user.UserCredentials
import org.apache.zeppelin.user.UsernamePassword
import org.apache.zeppelin.utils.SecurityUtils

/**
 * Credential Rest API.
 */
@Path("/credential")
@Produces("application/json")
class CredentialRestApi {
    internal var logger = LoggerFactory.getLogger(CredentialRestApi::class.java)
    private var credentials: Credentials? = null
    private val gson = Gson()

    @Context
    private val servReq: HttpServletRequest? = null

    constructor() {}

    constructor(credentials: Credentials) {
        this.credentials = credentials
    }

    /**
     * Put User Credentials REST API.
     *
     * @param message - JSON with entity, username, password.
     * @return JSON with status.OK
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @PUT
    @Throws(IOException::class, IllegalArgumentException::class)
    fun putCredentials(message: String): Response {
        val messageMap = gson.fromJson<Map<String, String>>(message,
                object : TypeToken<Map<String, String>>() {

                }.type)
        val entity = messageMap["entity"]
        val username = messageMap["username"]
        val password = messageMap["password"]

        if (Strings.isNullOrEmpty(entity)
                || Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(password)) {
            return JsonResponse<String>(Status.BAD_REQUEST).build()
        }

        val user = SecurityUtils.principal
        logger.info("Update credentials for user {} entity {}", user, entity)
        val uc = credentials!!.getUserCredentials(user)
        uc.putUsernamePassword(entity, UsernamePassword(username, password))
        credentials!!.putUserCredentials(user, uc)
        return JsonResponse<String>(Status.OK).build()
    }

    /**
     * Get User Credentials list REST API.
     *
     * @param
     * @return JSON with status.OK
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @GET
    @Throws(IOException::class, IllegalArgumentException::class)
    fun getCredentials(message: String): Response {
        val user = SecurityUtils.principal
        logger.info("getCredentials credentials for user {} ", user)
        val uc = credentials!!.getUserCredentials(user)
        return JsonResponse(Status.OK, uc).build()
    }

    /**
     * Remove User Credentials REST API.
     *
     * @param
     * @return JSON with status.OK
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @DELETE
    @Throws(IOException::class, IllegalArgumentException::class)
    fun removeCredentials(message: String): Response {
        val user = SecurityUtils.principal
        logger.info("removeCredentials credentials for user {} ", user)
        val uc = credentials!!.removeUserCredentials(user) ?: return JsonResponse<String>(Status.NOT_FOUND).build()
        return JsonResponse<String>(Status.OK).build()
    }

    /**
     * Remove Entity of User Credential entity REST API.
     *
     * @param
     * @return JSON with status.OK
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @DELETE
    @Path("{entity}")
    @Throws(IOException::class, IllegalArgumentException::class)
    fun removeCredentialEntity(@PathParam("entity") entity: String): Response {
        val user = SecurityUtils.principal
        logger.info("removeCredentialEntity for user {} entity {}", user, entity)
        return if (credentials!!.removeCredentialEntity(user, entity) == false) {
            JsonResponse<String>(Status.NOT_FOUND).build()
        } else JsonResponse<String>(Status.OK).build()
    }
}

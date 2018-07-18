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

import org.apache.log4j.Level
import org.apache.log4j.Logger

import java.util.HashMap

import javax.servlet.http.HttpServletRequest
import javax.ws.rs.GET
import javax.ws.rs.PUT
import javax.ws.rs.Path
import javax.ws.rs.PathParam
import javax.ws.rs.core.Context
import javax.ws.rs.core.Response

import org.apache.zeppelin.annotation.ZeppelinApi
import org.apache.zeppelin.server.JsonResponse
import org.apache.zeppelin.util.Util

/**
 * Zeppelin root rest api endpoint.
 *
 * @since 0.3.4
 */
@Path("/")
class ZeppelinRestApi {

    /**
     * Get the root endpoint Return always 200.
     *
     * @return 200 response
     */
    val root: Response
        @GET
        get() = Response.ok().build()

    val version: Response
        @GET
        @Path("version")
        @ZeppelinApi
        get() {
            val versionInfo = HashMap<String, String>()
            versionInfo["version"] = Util.getVersion()
            versionInfo["git-commit-id"] = Util.getGitCommitId()
            versionInfo["git-timestamp"] = Util.getGitTimestamp()

            return JsonResponse<Map<String, String>>(Response.Status.OK, "Zeppelin version", versionInfo).build()
        }

    /**
     * Set the log level for root logger.
     *
     * @param request
     * @param logLevel new log level for Rootlogger
     * @return
     */
    @PUT
    @Path("log/level/{logLevel}")
    fun changeRootLogLevel(@Context request: HttpServletRequest,
                           @PathParam("logLevel") logLevel: String): Response {
        val level = Level.toLevel(logLevel)
        if (logLevel.toLowerCase().equals(level.toString().toLowerCase(), ignoreCase = true)) {
            Logger.getRootLogger().level = level
            return JsonResponse<Any>(Response.Status.OK).build()
        } else {
            return JsonResponse<Any>(Response.Status.NOT_ACCEPTABLE,
                    "Please check LOG level specified. Valid values: DEBUG, ERROR, FATAL, " + "INFO, TRACE, WARN").build()
        }
    }
}

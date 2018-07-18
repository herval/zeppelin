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

import com.google.common.collect.Maps
import javax.validation.constraints.NotNull
import org.apache.commons.lang.exception.ExceptionUtils
import org.apache.zeppelin.notebook.socket.Message
import org.apache.zeppelin.notebook.socket.Message.OP
import org.apache.zeppelin.socket.ServiceCallback
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.sonatype.aether.repository.RemoteRepository

import java.io.IOException

import javax.ws.rs.DELETE
import javax.ws.rs.GET
import javax.ws.rs.POST
import javax.ws.rs.PUT
import javax.ws.rs.Path
import javax.ws.rs.PathParam
import javax.ws.rs.Produces
import javax.ws.rs.core.Response
import javax.ws.rs.core.Response.Status

import org.apache.zeppelin.annotation.ZeppelinApi
import org.apache.zeppelin.dep.Repository
import org.apache.zeppelin.interpreter.InterpreterException
import org.apache.zeppelin.interpreter.InterpreterPropertyType
import org.apache.zeppelin.interpreter.InterpreterSetting
import org.apache.zeppelin.interpreter.InterpreterSettingManager
import org.apache.zeppelin.rest.message.InterpreterInstallationRequest
import org.apache.zeppelin.rest.message.NewInterpreterSettingRequest
import org.apache.zeppelin.rest.message.RestartInterpreterRequest
import org.apache.zeppelin.rest.message.UpdateInterpreterSettingRequest
import org.apache.zeppelin.server.JsonResponse
import org.apache.zeppelin.service.InterpreterService
import org.apache.zeppelin.socket.NotebookServer
import org.apache.zeppelin.utils.SecurityUtils

/**
 * Interpreter Rest API.
 */
@Path("/interpreter")
@Produces("application/json")
class InterpreterRestApi(
        private val interpreterService: InterpreterService,
        private val interpreterSettingManager: InterpreterSettingManager,
        private val notebookServer: NotebookServer) {

    /**
     * List all interpreter settings.
     */
    @GET
    @Path("setting")
    @ZeppelinApi
    fun listSettings(): Response {
        return JsonResponse(Status.OK, "", interpreterSettingManager.get()).build()
    }

    /**
     * Get a setting.
     */
    @GET
    @Path("setting/{settingId}")
    @ZeppelinApi
    fun getSetting(@PathParam("settingId") settingId: String): Response {
        try {
            val setting = interpreterSettingManager.get(settingId)
            return if (setting == null) {
                JsonResponse<Any>(Status.NOT_FOUND).build()
            } else {
                JsonResponse(Status.OK, "", setting).build()
            }
        } catch (e: NullPointerException) {
            logger.error("Exception in InterpreterRestApi while creating ", e)
            return JsonResponse<String?>(Status.INTERNAL_SERVER_ERROR, e.message!!,
                    ExceptionUtils.getStackTrace(e)).build()
        }

    }

    /**
     * Add new interpreter setting.
     *
     * @param message NewInterpreterSettingRequest
     */
    @POST
    @Path("setting")
    @ZeppelinApi
    fun newSettings(message: String): Response {
        try {
            val request = NewInterpreterSettingRequest.fromJson(message)
                    ?: return JsonResponse<Any>(Status.BAD_REQUEST).build()

            val interpreterSetting = interpreterSettingManager
                    .createNewSetting(request.name, request.group, request.dependencies,
                            request.option, request.properties)
            logger.info("new setting created with {}", interpreterSetting.id)
            return JsonResponse(Status.OK, "", interpreterSetting).build()
        } catch (e: IOException) {
            logger.error("Exception in InterpreterRestApi while creating ", e)
            return JsonResponse<String?>(Status.NOT_FOUND, e.message!!, ExceptionUtils.getStackTrace(e))
                    .build()
        }

    }

    @PUT
    @Path("setting/{settingId}")
    @ZeppelinApi
    fun updateSetting(message: String, @PathParam("settingId") settingId: String): Response {
        logger.info("Update interpreterSetting {}", settingId)

        try {
            val request = UpdateInterpreterSettingRequest.fromJson(message)
            interpreterSettingManager
                    .setPropertyAndRestart(settingId, request.option, request.properties,
                            request.dependencies)
        } catch (e: InterpreterException) {
            logger.error("Exception in InterpreterRestApi while updateSetting ", e)
            return JsonResponse<String?>(Status.NOT_FOUND, e.message!!, ExceptionUtils.getStackTrace(e))
                    .build()
        } catch (e: IOException) {
            logger.error("Exception in InterpreterRestApi while updateSetting ", e)
            return JsonResponse<String?>(Status.INTERNAL_SERVER_ERROR, e.message!!,
                    ExceptionUtils.getStackTrace(e)).build()
        }

        val setting = interpreterSettingManager.get(settingId)
                ?: return JsonResponse(Status.NOT_FOUND, "", settingId).build()
        return JsonResponse(Status.OK, "", setting).build()
    }

    /**
     * Remove interpreter setting.
     */
    @DELETE
    @Path("setting/{settingId}")
    @ZeppelinApi
    @Throws(IOException::class)
    fun removeSetting(@PathParam("settingId") settingId: String): Response {
        logger.info("Remove interpreterSetting {}", settingId)
        interpreterSettingManager.remove(settingId)
        return JsonResponse<String?>(Status.OK).build()
    }

    /**
     * Restart interpreter setting.
     */
    @PUT
    @Path("setting/restart/{settingId}")
    @ZeppelinApi
    fun restartSetting(message: String, @PathParam("settingId") settingId: String): Response {
        logger.info("Restart interpreterSetting {}, msg={}", settingId, message)

        val setting = interpreterSettingManager.get(settingId)
        try {
            val request = RestartInterpreterRequest.fromJson(message)

            val noteId = request?.noteId
            if (null == noteId) {
                interpreterSettingManager.close(settingId)
            } else {
                interpreterSettingManager.restart(settingId, noteId, SecurityUtils.principal)
            }
            notebookServer.clearParagraphRuntimeInfo(setting)

        } catch (e: InterpreterException) {
            logger.error("Exception in InterpreterRestApi while restartSetting ", e)
            return JsonResponse<String?>(Status.NOT_FOUND, e.message!!, ExceptionUtils.getStackTrace(e))
                    .build()
        }

        return if (setting == null) {
            JsonResponse(Status.NOT_FOUND, "", settingId).build()
        } else JsonResponse(Status.OK, "", setting).build()
    }

    /**
     * List all available interpreters by group.
     */
    @GET
    @ZeppelinApi
    fun listInterpreter(message: String): Response {
        val m = interpreterSettingManager.interpreterSettingTemplates
        return JsonResponse(Status.OK, "", m).build()
    }

    /**
     * List of dependency resolving repositories.
     */
    @GET
    @Path("repository")
    @ZeppelinApi
    fun listRepositories(): Response {
        val interpreterRepositories = interpreterSettingManager.repositories
        return JsonResponse(Status.OK, "", interpreterRepositories).build()
    }

    /**
     * Add new repository.
     *
     * @param message Repository
     */
    @POST
    @Path("repository")
    @ZeppelinApi
    fun addRepository(message: String): Response {
        try {
            val request = Repository.fromJson(message)
            interpreterSettingManager.addRepository(request.id, request.url,
                    request.isSnapshot, request.authentication, request.proxy)
            logger.info("New repository {} added", request.id)
        } catch (e: Exception) {
            logger.error("Exception in InterpreterRestApi while adding repository ", e)
            return JsonResponse<String?>(Status.INTERNAL_SERVER_ERROR, e.message!!,
                    ExceptionUtils.getStackTrace(e)).build()
        }

        return JsonResponse<String?>(Status.OK).build()
    }

    /**
     * Delete repository.
     *
     * @param repoId ID of repository
     */
    @DELETE
    @Path("repository/{repoId}")
    @ZeppelinApi
    fun removeRepository(@PathParam("repoId") repoId: String): Response {
        logger.info("Remove repository {}", repoId)
        try {
            interpreterSettingManager.removeRepository(repoId)
        } catch (e: Exception) {
            logger.error("Exception in InterpreterRestApi while removing repository ", e)
            return JsonResponse<String?>(Status.INTERNAL_SERVER_ERROR, e.message!!,
                    ExceptionUtils.getStackTrace(e)).build()
        }

        return JsonResponse<String?>(Status.OK).build()
    }

    /**
     * Get available types for property
     */
    @GET
    @Path("property/types")
    fun listInterpreterPropertyTypes(): Response {
        return JsonResponse(Status.OK, InterpreterPropertyType.getTypes()).build()
    }

    /** Install interpreter  */
    @POST
    @Path("install")
    @ZeppelinApi
    fun installInterpreter(@NotNull message: String): Response {
        logger.info("Install interpreter: {}", message)
        val request = InterpreterInstallationRequest.fromJson(message)

        try {
            interpreterService.installInterpreter(
                    request,
                    object : ServiceCallback {
                        override fun onStart(message: String) {
                            val m = Message(OP.INTERPRETER_INSTALL_STARTED)
                            val data = Maps.newHashMap<String, Any>()
                            data["result"] = "Starting"
                            data["message"] = message
                            m.data = data
                            notebookServer.broadcast(m)
                        }

                        override fun onSuccess(message: String) {
                            val m = Message(OP.INTERPRETER_INSTALL_RESULT)
                            val data = Maps.newHashMap<String, Any>()
                            data["result"] = "Succeed"
                            data["message"] = message
                            m.data = data
                            notebookServer.broadcast(m)
                        }

                        override fun onFailure(message: String) {
                            val m = Message(OP.INTERPRETER_INSTALL_RESULT)
                            val data = Maps.newHashMap<String, Any>()
                            data["result"] = "Failed"
                            data["message"] = message
                            m.data = data
                            notebookServer.broadcast(m)
                        }
                    })
        } catch (t: Throwable) {
            return JsonResponse<String?>(Status.INTERNAL_SERVER_ERROR, t.message).build()
        }

        return JsonResponse<Any>(Status.OK).build()
    }

    companion object {

        private val logger = LoggerFactory.getLogger(InterpreterRestApi::class.java)
    }
}

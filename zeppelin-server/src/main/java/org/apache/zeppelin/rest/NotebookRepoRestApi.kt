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

import com.google.common.collect.ImmutableMap
import com.google.gson.JsonSyntaxException

import org.apache.commons.lang.StringUtils
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.util.Collections

import javax.ws.rs.GET
import javax.ws.rs.PUT
import javax.ws.rs.Path
import javax.ws.rs.Produces
import javax.ws.rs.core.Response
import javax.ws.rs.core.Response.Status

import org.apache.zeppelin.annotation.ZeppelinApi
import org.apache.zeppelin.notebook.repo.NotebookRepoSync
import org.apache.zeppelin.notebook.repo.NotebookRepoWithSettings
import org.apache.zeppelin.rest.message.NotebookRepoSettingsRequest
import org.apache.zeppelin.server.JsonResponse
import org.apache.zeppelin.socket.NotebookServer
import org.apache.zeppelin.user.AuthenticationInfo
import org.apache.zeppelin.utils.SecurityUtils

/**
 * NoteRepo rest API endpoint.
 *
 */
@Path("/notebook-repositories")
@Produces("application/json")
class NotebookRepoRestApi(val noteRepos: NotebookRepoSync, val notebookWsServer: NotebookServer) {

    /**
     * List all notebook repository.
     */
    @GET
    @ZeppelinApi
    fun listRepoSettings(): Response {
        val subject = AuthenticationInfo(SecurityUtils.principal)
        LOG.info("Getting list of NoteRepo with Settings for user {}", subject.user)
        val settings = noteRepos.getNotebookRepos(subject)
        return JsonResponse(Status.OK, "", settings).build()
    }

    /**
     * Reload notebook repository.
     */
    @GET
    @Path("reload")
    @ZeppelinApi
    fun refreshRepo(): Response {
        val subject = AuthenticationInfo(SecurityUtils.principal)
        LOG.info("Reloading notebook repository for user {}", subject.user)
        notebookWsServer.broadcastReloadedNoteList(subject, null)
        return JsonResponse<Any?>(Status.OK, "", null).build()
    }

    /**
     * Update a specific note repo.
     *
     * @param payload
     * @return
     */
    @PUT
    @ZeppelinApi
    fun updateRepoSetting(payload: String): Response {
        if (StringUtils.isBlank(payload)) {
            return JsonResponse(Status.NOT_FOUND, "", emptyMap<Any, Any>()).build()
        }
        val subject = AuthenticationInfo(SecurityUtils.principal)
        val newSettings: NotebookRepoSettingsRequest
        try {
            newSettings = NotebookRepoSettingsRequest.fromJson(payload)
        } catch (e: JsonSyntaxException) {
            LOG.error("Cannot update notebook repo settings", e)
            return JsonResponse(Status.NOT_ACCEPTABLE, "",
                    ImmutableMap.of("error", "Invalid payload structure")).build()
        }

        if (NotebookRepoSettingsRequest.isEmpty(newSettings)) {
            LOG.error("Invalid property")
            return JsonResponse(Status.NOT_ACCEPTABLE, "",
                    ImmutableMap.of("error", "Invalid payload")).build()
        }
        LOG.info("User {} is going to change repo setting", subject.user)
        val updatedSettings = noteRepos.updateNotebookRepo(newSettings.name, newSettings.settings, subject)
        if (!updatedSettings.isEmpty) {
            LOG.info("Broadcasting note list to user {}", subject.user)
            notebookWsServer.broadcastReloadedNoteList(subject, null)
        }
        return JsonResponse(Status.OK, "", updatedSettings).build()
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(NotebookRepoRestApi::class.java)
    }
}

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

import com.google.common.collect.Sets
import com.google.common.reflect.TypeToken
import com.google.gson.Gson

import org.apache.commons.lang3.StringUtils
import org.quartz.CronExpression
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.io.IOException
import java.util.HashMap
import java.util.HashSet

import javax.ws.rs.DELETE
import javax.ws.rs.GET
import javax.ws.rs.POST
import javax.ws.rs.PUT
import javax.ws.rs.Path
import javax.ws.rs.PathParam
import javax.ws.rs.Produces
import javax.ws.rs.QueryParam
import javax.ws.rs.core.Response
import javax.ws.rs.core.Response.Status

import org.apache.zeppelin.annotation.ZeppelinApi
import org.apache.zeppelin.interpreter.InterpreterResult
import org.apache.zeppelin.notebook.Note
import org.apache.zeppelin.notebook.Notebook
import org.apache.zeppelin.notebook.NotebookAuthorization
import org.apache.zeppelin.notebook.Paragraph
import org.apache.zeppelin.rest.exception.BadRequestException
import org.apache.zeppelin.rest.exception.ForbiddenException
import org.apache.zeppelin.rest.exception.NotFoundException
import org.apache.zeppelin.rest.message.CronRequest
import org.apache.zeppelin.rest.message.NewNoteRequest
import org.apache.zeppelin.rest.message.NewParagraphRequest
import org.apache.zeppelin.rest.message.RunParagraphWithParametersRequest
import org.apache.zeppelin.rest.message.UpdateParagraphRequest
import org.apache.zeppelin.search.SearchService
import org.apache.zeppelin.server.JsonResponse
import org.apache.zeppelin.socket.NotebookServer
import org.apache.zeppelin.types.InterpreterSettingsList
import org.apache.zeppelin.user.AuthenticationInfo
import org.apache.zeppelin.utils.InterpreterBindingUtils
import org.apache.zeppelin.utils.SecurityUtils

/**
 * Rest api endpoint for the notebook.
 */
@Path("/notebook")
@Produces("application/json")
class NotebookRestApi(val notebook: Notebook, val notebookServer: NotebookServer, val noteSearchService: SearchService) {
    internal var gson = Gson()
    private val notebookAuthorization: NotebookAuthorization = notebook.notebookAuthorization

    private val blockNotAuthenticatedUserErrorMsg: String
        get() = "Only authenticated user can set the permission."

    val noteList: Response
        @GET
        @Path("/")
        @ZeppelinApi
        @Throws(IOException::class)
        get() {
            val subject = AuthenticationInfo(SecurityUtils.principal)
            val userAndRoles = SecurityUtils.roles
            userAndRoles.add(subject.user)
            val notesInfo = notebookServer.generateNotesInfo(false, subject,
                    userAndRoles)
            return JsonResponse(Status.OK, "", notesInfo).build()
        }

    /**
     * Get note jobs for job manager.
     *
     * @return JSON with status.OK
     * @throws IOException
     * @throws IllegalArgumentException
     */
    val jobListforNote: Response
        @GET
        @Path("jobmanager/")
        @ZeppelinApi
        @Throws(IOException::class, IllegalArgumentException::class)
        get() {
            LOG.info("Get note jobs for job manager")

            val subject = AuthenticationInfo(SecurityUtils.principal)
            val noteJobs = notebook
                    .getJobListByUnixTime(false, 0, subject)
            val response = HashMap<String, Any>()

            response["lastResponseUnixTime"] = System.currentTimeMillis()
            response["jobs"] = noteJobs

            return JsonResponse<Map<String, Any>>(Status.OK, response).build()
        }

    /**
     * Get note authorization information.
     */
    @GET
    @Path("{noteId}/permissions")
    @ZeppelinApi
    @Throws(IOException::class)
    fun getNotePermissions(@PathParam("noteId") noteId: String): Response {
        checkIfUserIsAnon(blockNotAuthenticatedUserErrorMsg)
        checkIfUserCanRead(noteId,
                "Insufficient privileges you cannot get the list of permissions for this note")
        val permissionsMap = HashMap<String, Set<String>>()
        permissionsMap["owners"] = notebookAuthorization.getOwners(noteId)
        permissionsMap["readers"] = notebookAuthorization.getReaders(noteId)
        permissionsMap["writers"] = notebookAuthorization.getWriters(noteId)
        permissionsMap["runners"] = notebookAuthorization.getRunners(noteId)
        return JsonResponse(Status.OK, "", permissionsMap).build()
    }

    private fun ownerPermissionError(current: Set<String>, allowed: Set<String>): String {
        LOG.info("Cannot change permissions. Connection owners {}. Allowed owners {}",
                current.toString(), allowed.toString())
        return "Insufficient privileges to change permissions.\n\n" +
                "Allowed owners: " + allowed.toString() + "\n\n" +
                "User belongs to: " + current.toString()
    }

    /*
   * Set of utils method to check if current user can perform action to the note.
   * Since we only have security on notebook level, from now we keep this logic in this class.
   * In the future we might want to generalize this for the rest of the api enmdpoints.
   */

    /**
     * Check if the current user is not authenticated(anonymous user) or not.
     */
    private fun checkIfUserIsAnon(errorMsg: String) {
        val isAuthenticated = SecurityUtils.isAuthenticated
        if (isAuthenticated && SecurityUtils.principal == "anonymous") {
            LOG.info("Anonymous user cannot set any permissions for this note.")
            throw ForbiddenException(errorMsg)
        }
    }

    /**
     * Check if the current user own the given note.
     */
    private fun checkIfUserIsOwner(noteId: String, errorMsg: String) {
        val userAndRoles = Sets.newHashSet<String>()
        userAndRoles.add(SecurityUtils.principal)
        userAndRoles.addAll(SecurityUtils.roles)
        if (!notebookAuthorization.isOwner(userAndRoles, noteId)) {
            throw ForbiddenException(errorMsg)
        }
    }

    /**
     * Check if the current user is either Owner or Writer for the given note.
     */
    private fun checkIfUserCanWrite(noteId: String, errorMsg: String) {
        val userAndRoles = Sets.newHashSet<String>()
        userAndRoles.add(SecurityUtils.principal)
        userAndRoles.addAll(SecurityUtils.roles)
        if (!notebookAuthorization.hasWriteAuthorization(userAndRoles, noteId)) {
            throw ForbiddenException(errorMsg)
        }
    }

    /**
     * Check if the current user can access (at least he have to be reader) the given note.
     */
    private fun checkIfUserCanRead(noteId: String, errorMsg: String) {
        val userAndRoles = Sets.newHashSet<String>()
        userAndRoles.add(SecurityUtils.principal)
        userAndRoles.addAll(SecurityUtils.roles)
        if (!notebookAuthorization.hasReadAuthorization(userAndRoles, noteId)) {
            throw ForbiddenException(errorMsg)
        }
    }

    /**
     * Check if the current user can run the given note.
     */
    private fun checkIfUserCanRun(noteId: String, errorMsg: String) {
        val userAndRoles = Sets.newHashSet<String>()
        userAndRoles.add(SecurityUtils.principal)
        userAndRoles.addAll(SecurityUtils.roles)
        if (!notebookAuthorization.hasRunAuthorization(userAndRoles, noteId)) {
            throw ForbiddenException(errorMsg)
        }
    }

    private fun checkIfNoteIsNotNull(note: Note?) {
        if (note == null) {
            throw NotFoundException("note not found")
        }
    }

    private fun checkIfNoteSupportsCron(note: Note) {
        if (!note.isCronSupported(notebook.conf)) {
            LOG.error("Cron is not enabled from Zeppelin server")
            throw ForbiddenException("Cron is not enabled from Zeppelin server")
        }
    }

    private fun checkIfParagraphIsNotNull(paragraph: Paragraph?) {
        if (paragraph == null) {
            throw NotFoundException("paragraph not found")
        }
    }

    /**
     * Set note authorization information.
     */
    @PUT
    @Path("{noteId}/permissions")
    @ZeppelinApi
    @Throws(IOException::class)
    fun putNotePermissions(@PathParam("noteId") noteId: String, req: String): Response {
        val principal = SecurityUtils.principal
        val roles = SecurityUtils.roles
        val userAndRoles = HashSet<String>()
        userAndRoles.add(principal)
        userAndRoles.addAll(roles)

        checkIfUserIsAnon(blockNotAuthenticatedUserErrorMsg)
        checkIfUserIsOwner(noteId,
                ownerPermissionError(userAndRoles, notebookAuthorization.getOwners(noteId)))

        val permMap = gson.fromJson<HashMap<String, HashSet<String>>>(req, object : TypeToken<HashMap<String, HashSet<String>>>() {

        }.type)
        val note = notebook.getNote(noteId)

        LOG.info("Set permissions {} {} {} {} {} {}", noteId, principal, permMap["owners"],
                permMap["readers"], permMap["runners"], permMap["writers"])

        val readers = permMap["readers"]
        var runners: HashSet<String>? = permMap["runners"]
        var owners = permMap["owners"]
        var writers: HashSet<String>? = permMap["writers"]
        // Set readers, if runners, writers and owners is empty -> set to user requesting the change
        if (readers != null && !readers.isEmpty()) {
            if (runners!!.isEmpty()) {
                runners = Sets.newHashSet<String>(SecurityUtils.principal)
            }
            if (writers!!.isEmpty()) {
                writers = Sets.newHashSet<String>(SecurityUtils.principal)
            }
            if (owners!!.isEmpty()) {
                owners = Sets.newHashSet<String>(SecurityUtils.principal)
            }
        }
        // Set runners, if writers and owners is empty -> set to user requesting the change
        if (runners != null && !runners.isEmpty()) {
            if (writers!!.isEmpty()) {
                writers = Sets.newHashSet<String>(SecurityUtils.principal)
            }
            if (owners!!.isEmpty()) {
                owners = Sets.newHashSet<String>(SecurityUtils.principal)
            }
        }
        // Set writers, if owners is empty -> set to user requesting the change
        if (writers != null && !writers.isEmpty()) {
            if (owners!!.isEmpty()) {
                owners = Sets.newHashSet<String>(SecurityUtils.principal)
            }
        }

        notebookAuthorization.setReaders(noteId, readers)
        notebookAuthorization.setRunners(noteId, runners)
        notebookAuthorization.setWriters(noteId, writers)
        notebookAuthorization.setOwners(noteId, owners)
        LOG.debug("After set permissions {} {} {} {}", notebookAuthorization.getOwners(noteId),
                notebookAuthorization.getReaders(noteId), notebookAuthorization.getRunners(noteId),
                notebookAuthorization.getWriters(noteId))
        val subject = AuthenticationInfo(SecurityUtils.principal)
        note.persist(subject)
        notebookServer.broadcastNote(note)
        notebookServer.broadcastNoteList(subject, userAndRoles)
        return JsonResponse<Any>(Status.OK).build()
    }

    /**
     * Bind a setting to note.
     *
     * @throws IOException
     */
    @PUT
    @Path("interpreter/bind/{noteId}")
    @ZeppelinApi
    @Throws(IOException::class)
    fun bind(@PathParam("noteId") noteId: String, req: String): Response {
        checkIfUserCanWrite(noteId,
                "Insufficient privileges you cannot bind any interpreters to this note")

        val settingIdList = gson.fromJson<List<String>>(req, object : TypeToken<List<String>>() {

        }.type)
        notebook.bindInterpretersToNote(SecurityUtils.principal, noteId, settingIdList)
        return JsonResponse<Any>(Status.OK).build()
    }

    /**
     * list bound setting.
     */
    @GET
    @Path("interpreter/bind/{noteId}")
    @ZeppelinApi
    fun bind(@PathParam("noteId") noteId: String): Response {
        checkIfUserCanRead(noteId, "Insufficient privileges you cannot get any interpreters settings")

        val settingList = InterpreterBindingUtils.getInterpreterBindings(notebook, noteId)
        notebookServer.broadcastInterpreterBindings(noteId, settingList)
        return JsonResponse(Status.OK, "", settingList).build()
    }

    @GET
    @Path("{noteId}")
    @ZeppelinApi
    @Throws(IOException::class)
    fun getNote(@PathParam("noteId") noteId: String): Response {
        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        checkIfUserCanRead(noteId, "Insufficient privileges you cannot get this note")

        return JsonResponse(Status.OK, "", note).build()
    }

    /**
     * export note REST API.
     *
     * @param noteId ID of Note
     * @return note JSON with status.OK
     * @throws IOException
     */
    @GET
    @Path("export/{noteId}")
    @ZeppelinApi
    @Throws(IOException::class)
    fun exportNote(@PathParam("noteId") noteId: String): Response {
        checkIfUserCanRead(noteId, "Insufficient privileges you cannot export this note")
        val exportJson = notebook.exportNote(noteId)
        return JsonResponse(Status.OK, "", exportJson).build()
    }

    /**
     * import new note REST API.
     *
     * @param req - note Json
     * @return JSON with new note ID
     * @throws IOException
     */
    @POST
    @Path("import")
    @ZeppelinApi
    @Throws(IOException::class)
    fun importNote(req: String): Response {
        val subject = AuthenticationInfo(SecurityUtils.principal)
        val newNote = notebook.importNote(req, null, subject)
        return JsonResponse(Status.OK, "", newNote.id).build()
    }

    /**
     * Create new note REST API.
     *
     * @param message - JSON with new note name
     * @return JSON with new note ID
     * @throws IOException
     */
    @POST
    @Path("/")
    @ZeppelinApi
    @Throws(IOException::class)
    fun createNote(message: String): Response {
        val user = SecurityUtils.principal
        LOG.info("Create new note by JSON {}", message)
        val request = NewNoteRequest.fromJson(message)
        val subject = AuthenticationInfo(user)
        val note = notebook.createNote(subject)
        if (request != null) {
            val initialParagraphs = request.paragraphs
            if (initialParagraphs != null) {
                for (paragraphRequest in initialParagraphs) {
                    val p = note.addNewParagraph(subject)
                    initParagraph(p, paragraphRequest, user)
                }
            }
        }
        note.addNewParagraph(subject) // add one paragraph to the last
        var noteName = request.name
        if (noteName!!.isEmpty()) {
            noteName = "Note " + note.id
        }

        note.name = noteName
        note.persist(subject)
        note.setCronSupported(notebook.conf)
        notebookServer.broadcastNote(note)
        notebookServer.broadcastNoteList(subject, SecurityUtils.roles)
        return JsonResponse(Status.OK, "", note.id).build()
    }

    /**
     * Delete note REST API.
     *
     * @param noteId ID of Note
     * @return JSON with status.OK
     * @throws IOException
     */
    @DELETE
    @Path("{noteId}")
    @ZeppelinApi
    @Throws(IOException::class)
    fun deleteNote(@PathParam("noteId") noteId: String): Response {
        LOG.info("Delete note {} ", noteId)
        checkIfUserIsOwner(noteId, "Insufficient privileges you cannot delete this note")
        val subject = AuthenticationInfo(SecurityUtils.principal)
        if (!noteId.isEmpty()) {
            val note = notebook.getNote(noteId)
            if (note != null) {
                notebook.removeNote(noteId, subject)
            }
        }

        notebookServer.broadcastNoteList(subject, SecurityUtils.roles)
        return JsonResponse<Any>(Status.OK, "").build()
    }

    /**
     * Clone note REST API.
     *
     * @param noteId ID of Note
     * @return JSON with status.OK
     * @throws IOException
     * @throws CloneNotSupportedException
     * @throws IllegalArgumentException
     */
    @POST
    @Path("{noteId}")
    @ZeppelinApi
    @Throws(IOException::class, CloneNotSupportedException::class, IllegalArgumentException::class)
    fun cloneNote(@PathParam("noteId") noteId: String, message: String): Response {
        LOG.info("clone note by JSON {}", message)
        checkIfUserCanWrite(noteId, "Insufficient privileges you cannot clone this note")
        val request = NewNoteRequest.fromJson(message)
        var newNoteName: String? = null
        if (request != null) {
            newNoteName = request.name
        }
        val subject = AuthenticationInfo(SecurityUtils.principal)
        val newNote = notebook.cloneNote(noteId, newNoteName, subject)
        notebookServer.broadcastNote(newNote)
        notebookServer.broadcastNoteList(subject, SecurityUtils.roles)
        return JsonResponse(Status.OK, "", newNote.id).build()
    }

    /**
     * Insert paragraph REST API.
     *
     * @param message - JSON containing paragraph's information
     * @return JSON with status.OK
     * @throws IOException
     */
    @POST
    @Path("{noteId}/paragraph")
    @ZeppelinApi
    @Throws(IOException::class)
    fun insertParagraph(@PathParam("noteId") noteId: String, message: String): Response {
        val user = SecurityUtils.principal
        LOG.info("insert paragraph {} {}", noteId, message)

        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        checkIfUserCanWrite(noteId, "Insufficient privileges you cannot add paragraph to this note")

        val request = NewParagraphRequest.fromJson(message)
        val subject = AuthenticationInfo(user)
        val p: Paragraph
        val indexDouble = request.index
        if (indexDouble == null) {
            p = note.addNewParagraph(subject)
        } else {
            p = note.insertNewParagraph(indexDouble.toInt(), subject)
        }
        initParagraph(p, request, user)
        note.persist(subject)
        notebookServer.broadcastNote(note)
        return JsonResponse(Status.OK, "", p.id).build()
    }

    /**
     * Get paragraph REST API.
     *
     * @param noteId ID of Note
     * @return JSON with information of the paragraph
     * @throws IOException
     */
    @GET
    @Path("{noteId}/paragraph/{paragraphId}")
    @ZeppelinApi
    @Throws(IOException::class)
    fun getParagraph(@PathParam("noteId") noteId: String,
                     @PathParam("paragraphId") paragraphId: String): Response {
        LOG.info("get paragraph {} {}", noteId, paragraphId)

        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        checkIfUserCanRead(noteId, "Insufficient privileges you cannot get this paragraph")
        val p = note.getParagraph(paragraphId)
        checkIfParagraphIsNotNull(p)

        return JsonResponse(Status.OK, "", p).build()
    }

    /**
     * Update paragraph.
     *
     * @param message json containing the "text" and optionally the "title" of the paragraph, e.g.
     * {"text" : "updated text", "title" : "Updated title" }
     */
    @PUT
    @Path("{noteId}/paragraph/{paragraphId}")
    @ZeppelinApi
    @Throws(IOException::class)
    fun updateParagraph(@PathParam("noteId") noteId: String,
                        @PathParam("paragraphId") paragraphId: String, message: String): Response {
        val user = SecurityUtils.principal
        LOG.info("{} will update paragraph {} {}", user, noteId, paragraphId)

        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        checkIfUserCanWrite(noteId, "Insufficient privileges you cannot update this paragraph")
        val p = note.getParagraph(paragraphId)
        checkIfParagraphIsNotNull(p)

        val updatedParagraph = gson.fromJson(message, UpdateParagraphRequest::class.java)
        p!!.text = updatedParagraph.text

        if (updatedParagraph.title != null) {
            p.title = updatedParagraph.title
        }

        val subject = AuthenticationInfo(user)
        note.persist(subject)
        notebookServer.broadcastParagraph(note, p)
        return JsonResponse<Any>(Status.OK, "").build()
    }

    @PUT
    @Path("{noteId}/paragraph/{paragraphId}/config")
    @ZeppelinApi
    @Throws(IOException::class)
    fun updateParagraphConfig(@PathParam("noteId") noteId: String,
                              @PathParam("paragraphId") paragraphId: String, message: String): Response {
        val user = SecurityUtils.principal
        LOG.info("{} will update paragraph config {} {}", user, noteId, paragraphId)

        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        checkIfUserCanWrite(noteId, "Insufficient privileges you cannot update this paragraph config")
        val p = note.getParagraph(paragraphId)
        checkIfParagraphIsNotNull(p)

        val newConfig = gson.fromJson(message, HashMap::class.java) as? Map<String, Any>
        configureParagraph(p, newConfig, user)
        val subject = AuthenticationInfo(user)
        note.persist(subject)
        return JsonResponse(Status.OK, "", p).build()
    }

    /**
     * Move paragraph REST API.
     *
     * @param newIndex - new index to move
     * @return JSON with status.OK
     * @throws IOException
     */
    @POST
    @Path("{noteId}/paragraph/{paragraphId}/move/{newIndex}")
    @ZeppelinApi
    @Throws(IOException::class)
    fun moveParagraph(@PathParam("noteId") noteId: String,
                      @PathParam("paragraphId") paragraphId: String, @PathParam("newIndex") newIndex: String): Response {
        LOG.info("move paragraph {} {} {}", noteId, paragraphId, newIndex)

        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        checkIfUserCanWrite(noteId, "Insufficient privileges you cannot move paragraph")

        val p = note.getParagraph(paragraphId)
        checkIfParagraphIsNotNull(p)

        try {
            note.moveParagraph(paragraphId, Integer.parseInt(newIndex), true)

            val subject = AuthenticationInfo(SecurityUtils.principal)
            note.persist(subject)
            notebookServer.broadcastNote(note)
            return JsonResponse<String>(Status.OK, "").build()
        } catch (e: IndexOutOfBoundsException) {
            LOG.error("Exception in NotebookRestApi while moveParagraph ", e)
            return JsonResponse<String>(Status.BAD_REQUEST, "paragraph's new index is out of bound").build()
        }

    }

    /**
     * Delete paragraph REST API.
     *
     * @param noteId ID of Note
     * @return JSON with status.OK
     * @throws IOException
     */
    @DELETE
    @Path("{noteId}/paragraph/{paragraphId}")
    @ZeppelinApi
    @Throws(IOException::class)
    fun deleteParagraph(@PathParam("noteId") noteId: String,
                        @PathParam("paragraphId") paragraphId: String): Response {
        LOG.info("delete paragraph {} {}", noteId, paragraphId)

        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        checkIfUserCanRead(noteId,
                "Insufficient privileges you cannot remove paragraph from this note")

        val p = note.getParagraph(paragraphId)
        checkIfParagraphIsNotNull(p)

        val subject = AuthenticationInfo(SecurityUtils.principal)
        note.removeParagraph(SecurityUtils.principal, paragraphId)
        note.persist(subject)
        notebookServer.broadcastNote(note)

        return JsonResponse<String>(Status.OK, "").build()
    }

    /**
     * Clear result of all paragraphs REST API.
     *
     * @param noteId ID of Note
     * @return JSON with status.ok
     */
    @PUT
    @Path("{noteId}/clear")
    @ZeppelinApi
    @Throws(IOException::class)
    fun clearAllParagraphOutput(@PathParam("noteId") noteId: String): Response {
        LOG.info("clear all paragraph output of note {}", noteId)
        checkIfUserCanWrite(noteId, "Insufficient privileges you cannot clear this note")

        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        note.clearAllParagraphOutput()

        return JsonResponse<String>(Status.OK, "").build()
    }

    /**
     * Run note jobs REST API.
     *
     * @param noteId ID of Note
     * @return JSON with status.OK
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @POST
    @Path("job/{noteId}")
    @ZeppelinApi
    @Throws(IOException::class, IllegalArgumentException::class)
    fun runNoteJobs(@PathParam("noteId") noteId: String,
                    @QueryParam("waitToFinish") waitToFinish: Boolean?): Response {
        val blocking = if (waitToFinish == null) true else waitToFinish
        LOG.info("run note jobs {} waitToFinish: {}", noteId, blocking)
        val note = notebook.getNote(noteId)
        val subject = AuthenticationInfo(SecurityUtils.principal)
        checkIfNoteIsNotNull(note)
        checkIfUserCanRun(noteId, "Insufficient privileges you cannot run job for this note")

        try {
            note.runAll(subject, blocking)
        } catch (ex: Exception) {
            LOG.error("Exception from run", ex)
            return JsonResponse<Any>(Status.PRECONDITION_FAILED,
                    ex.message + "- Not selected or Invalid Interpreter bind").build()
        }

        return JsonResponse<Any>(Status.OK).build()
    }

    /**
     * Stop(delete) note jobs REST API.
     *
     * @param noteId ID of Note
     * @return JSON with status.OK
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @DELETE
    @Path("job/{noteId}")
    @ZeppelinApi
    @Throws(IOException::class, IllegalArgumentException::class)
    fun stopNoteJobs(@PathParam("noteId") noteId: String): Response {
        LOG.info("stop note jobs {} ", noteId)
        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        checkIfUserCanRun(noteId, "Insufficient privileges you cannot stop this job for this note")

        for (p in note.paragraphs) {
            if (!p.isTerminated) {
                p.abort()
            }
        }
        return JsonResponse<Any>(Status.OK).build()
    }

    /**
     * Get note job status REST API.
     *
     * @param noteId ID of Note
     * @return JSON with status.OK
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @GET
    @Path("job/{noteId}")
    @ZeppelinApi
    @Throws(IOException::class, IllegalArgumentException::class)
    fun getNoteJobStatus(@PathParam("noteId") noteId: String): Response {
        LOG.info("get note job status.")
        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        checkIfUserCanRead(noteId, "Insufficient privileges you cannot get job status")

        return JsonResponse(Status.OK, "", note.generateParagraphsInfo()).build()
    }

    /**
     * Get note paragraph job status REST API.
     *
     * @param noteId ID of Note
     * @param paragraphId ID of Paragraph
     * @return JSON with status.OK
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @GET
    @Path("job/{noteId}/{paragraphId}")
    @ZeppelinApi
    @Throws(IOException::class, IllegalArgumentException::class)
    fun getNoteParagraphJobStatus(@PathParam("noteId") noteId: String,
                                  @PathParam("paragraphId") paragraphId: String): Response {
        LOG.info("get note paragraph job status.")
        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        checkIfUserCanRead(noteId, "Insufficient privileges you cannot get job status")

        val paragraph = note.getParagraph(paragraphId)
        checkIfParagraphIsNotNull(paragraph)

        return JsonResponse(Status.OK, "", note.generateSingleParagraphInfo(paragraphId)).build()
    }

    /**
     * Run asynchronously paragraph job REST API.
     *
     * @param message - JSON with params if user wants to update dynamic form's value
     * null, empty string, empty json if user doesn't want to update
     * @return JSON with status.OK
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @POST
    @Path("job/{noteId}/{paragraphId}")
    @ZeppelinApi
    @Throws(IOException::class, IllegalArgumentException::class)
    fun runParagraph(@PathParam("noteId") noteId: String,
                     @PathParam("paragraphId") paragraphId: String, message: String): Response {
        LOG.info("run paragraph job asynchronously {} {} {}", noteId, paragraphId, message)

        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        checkIfUserCanRun(noteId, "Insufficient privileges you cannot run job for this note")
        val paragraph = note.getParagraph(paragraphId)
        checkIfParagraphIsNotNull(paragraph)

        // handle params if presented
        handleParagraphParams(message, note, paragraph)

        val subject = AuthenticationInfo(SecurityUtils.principal)

        paragraph!!.authenticationInfo = subject
        note.persist(subject)

        note.run(paragraph.id)
        return JsonResponse<Any>(Status.OK).build()
    }

    /**
     * Run synchronously a paragraph REST API.
     *
     * @param noteId - noteId
     * @param paragraphId - paragraphId
     * @param message - JSON with params if user wants to update dynamic form's value
     * null, empty string, empty json if user doesn't want to update
     *
     * @return JSON with status.OK
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @POST
    @Path("run/{noteId}/{paragraphId}")
    @ZeppelinApi
    @Throws(IOException::class, IllegalArgumentException::class)
    fun runParagraphSynchronously(@PathParam("noteId") noteId: String,
                                  @PathParam("paragraphId") paragraphId: String, message: String): Response {
        LOG.info("run paragraph synchronously {} {} {}", noteId, paragraphId, message)

        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        checkIfUserCanRun(noteId, "Insufficient privileges you cannot run paragraph")
        val paragraph = note.getParagraph(paragraphId)
        checkIfParagraphIsNotNull(paragraph)

        // handle params if presented
        handleParagraphParams(message, note, paragraph)

        if (paragraph!!.listener == null) {
            note.initializeJobListenerForParagraph(paragraph)
        }

        val subject = AuthenticationInfo(SecurityUtils.principal)
        paragraph.authenticationInfo = subject

        paragraph.run()

        val result = paragraph.result

        return if (result.code() == InterpreterResult.Code.SUCCESS) {
            JsonResponse(Status.OK, result).build()
        } else {
            JsonResponse(Status.INTERNAL_SERVER_ERROR, result).build()
        }
    }

    /**
     * Stop(delete) paragraph job REST API.
     *
     * @param noteId  ID of Note
     * @param paragraphId ID of Paragraph
     * @return JSON with status.OK
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @DELETE
    @Path("job/{noteId}/{paragraphId}")
    @ZeppelinApi
    @Throws(IOException::class, IllegalArgumentException::class)
    fun stopParagraph(@PathParam("noteId") noteId: String,
                      @PathParam("paragraphId") paragraphId: String): Response {
        LOG.info("stop paragraph job {} ", noteId)
        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        checkIfUserCanRun(noteId, "Insufficient privileges you cannot stop paragraph")
        val p = note.getParagraph(paragraphId)
        checkIfParagraphIsNotNull(p)
        p!!.abort()
        return JsonResponse<Any>(Status.OK).build()
    }

    /**
     * Register cron job REST API.
     *
     * @param message - JSON with cron expressions.
     * @return JSON with status.OK
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @POST
    @Path("cron/{noteId}")
    @ZeppelinApi
    @Throws(IOException::class, IllegalArgumentException::class)
    fun registerCronJob(@PathParam("noteId") noteId: String, message: String): Response {
        LOG.info("Register cron job note={} request cron msg={}", noteId, message)

        val request = CronRequest.fromJson(message)

        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        checkIfUserCanRun(noteId, "Insufficient privileges you cannot set a cron job for this note")
        checkIfNoteSupportsCron(note)

        if (!CronExpression.isValidExpression(request.cronString)) {
            return JsonResponse<Any>(Status.BAD_REQUEST, "wrong cron expressions.").build()
        }

        val config = note.config
        config["cron"] = request.cronString
        note.config = config
        notebook.refreshCron(note.id)

        return JsonResponse<Any>(Status.OK).build()
    }

    /**
     * Remove cron job REST API.
     *
     * @param noteId ID of Note
     * @return JSON with status.OK
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @DELETE
    @Path("cron/{noteId}")
    @ZeppelinApi
    @Throws(IOException::class, IllegalArgumentException::class)
    fun removeCronJob(@PathParam("noteId") noteId: String): Response {
        LOG.info("Remove cron job note {}", noteId)

        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        checkIfUserIsOwner(noteId,
                "Insufficient privileges you cannot remove this cron job from this note")
        checkIfNoteSupportsCron(note)

        val config = note.config
        config["cron"] = null
        note.config = config
        notebook.refreshCron(note.id)

        return JsonResponse<Any>(Status.OK).build()
    }

    /**
     * Get cron job REST API.
     *
     * @param noteId ID of Note
     * @return JSON with status.OK
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @GET
    @Path("cron/{noteId}")
    @ZeppelinApi
    @Throws(IOException::class, IllegalArgumentException::class)
    fun getCronJob(@PathParam("noteId") noteId: String): Response {
        LOG.info("Get cron job note {}", noteId)

        val note = notebook.getNote(noteId)
        checkIfNoteIsNotNull(note)
        checkIfUserCanRead(noteId, "Insufficient privileges you cannot get cron information")
        checkIfNoteSupportsCron(note)

        return JsonResponse<Any>(Status.OK, note.config["cron"]!!).build()
    }

    /**
     * Get updated note jobs for job manager
     *
     * Return the `Note` change information within the post unix timestamp.
     *
     * @return JSON with status.OK
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @GET
    @Path("jobmanager/{lastUpdateUnixtime}/")
    @ZeppelinApi
    @Throws(IOException::class, IllegalArgumentException::class)
    fun getUpdatedJobListforNote(@PathParam("lastUpdateUnixtime") lastUpdateUnixTime: Long): Response {
        LOG.info("Get updated note jobs lastUpdateTime {}", lastUpdateUnixTime)

        val noteJobs: List<Map<String, Any>>
        val subject = AuthenticationInfo(SecurityUtils.principal)
        noteJobs = notebook.getJobListByUnixTime(false, lastUpdateUnixTime, subject)
        val response = HashMap<String, Any>()

        response["lastResponseUnixTime"] = System.currentTimeMillis()
        response["jobs"] = noteJobs

        return JsonResponse<Map<String, Any>>(Status.OK, response).build()
    }

    /**
     * Search for a Notes with permissions.
     */
    @GET
    @Path("search")
    @ZeppelinApi
    fun search(@QueryParam("q") queryTerm: String): Response {
        LOG.info("Searching notes for: {}", queryTerm)
        val principal = SecurityUtils.principal
        val roles = SecurityUtils.roles
        val userAndRoles = HashSet<String>()
        userAndRoles.add(principal)
        userAndRoles.addAll(roles)
        val notesFound = noteSearchService.query(queryTerm)
        var i = 0
        while (i < notesFound.size) {
            val ids = notesFound[i]["id"]!!.split("/".toRegex(), 2).toTypedArray()
            val noteId = ids[0]
            if (!notebookAuthorization.isOwner(noteId, userAndRoles) &&
                    !notebookAuthorization.isReader(noteId, userAndRoles) &&
                    !notebookAuthorization.isWriter(noteId, userAndRoles) &&
                    !notebookAuthorization.isRunner(noteId, userAndRoles)) {
                notesFound.removeAt(i)
                i--
            }
            i++
        }
        LOG.info("{} notes found", notesFound.size)
        return JsonResponse(Status.OK, notesFound).build()
    }


    @Throws(IOException::class)
    private fun handleParagraphParams(message: String, note: Note, paragraph: Paragraph) {
        // handle params if presented
        if (!StringUtils.isEmpty(message)) {
            val request = RunParagraphWithParametersRequest.fromJson(message)
            val paramsForUpdating = request.params
            if (paramsForUpdating != null) {
                paragraph.settings.params.putAll(paramsForUpdating)
                val subject = AuthenticationInfo(SecurityUtils.principal)
                note.persist(subject)
            }
        }
    }

    private fun initParagraph(p: Paragraph, request: NewParagraphRequest, user: String) {
        LOG.info("Init Paragraph for user {}", user)
        checkIfParagraphIsNotNull(p)
        p.title = request.title
        p.text = request.text
        val config = request.config
        if (config != null && !config.isEmpty()) {
            configureParagraph(p, config, user)
        }
    }

    private fun configureParagraph(p: Paragraph, newConfig: Map<String, Any>?, user: String) {
        LOG.info("Configure Paragraph for user {}", user)
        if (newConfig == null || newConfig.isEmpty()) {
            LOG.warn("{} is trying to update paragraph {} of note {} with empty config",
                    user, p.id, p.note.id)
            throw BadRequestException("paragraph config cannot be empty")
        }
        val origConfig = p.config
        for ((key, value) in newConfig) {
            origConfig[key] = value
        }

        p.config = origConfig
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(NotebookRestApi::class.java)
    }
}

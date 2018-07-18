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
package org.apache.zeppelin.socket

import com.google.common.base.Strings
import com.google.common.collect.Queues
import com.google.common.collect.Sets
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import org.apache.commons.lang.StringUtils
import org.apache.zeppelin.conf.ZeppelinConfiguration
import org.apache.zeppelin.conf.ZeppelinConfiguration.ConfVars
import org.apache.zeppelin.display.AngularObject
import org.apache.zeppelin.display.AngularObjectRegistry
import org.apache.zeppelin.display.AngularObjectRegistryListener
import org.apache.zeppelin.display.GUI
import org.apache.zeppelin.display.Input
import org.apache.zeppelin.helium.ApplicationEventListener
import org.apache.zeppelin.helium.HeliumPackage
import org.apache.zeppelin.interpreter.Interpreter
import org.apache.zeppelin.interpreter.InterpreterGroup
import org.apache.zeppelin.interpreter.InterpreterNotFoundException
import org.apache.zeppelin.interpreter.InterpreterResult
import org.apache.zeppelin.interpreter.InterpreterResultMessage
import org.apache.zeppelin.interpreter.InterpreterSetting
import org.apache.zeppelin.interpreter.remote.RemoteAngularObjectRegistry
import org.apache.zeppelin.interpreter.remote.RemoteInterpreterProcessListener
import org.apache.zeppelin.interpreter.thrift.InterpreterCompletion
import org.apache.zeppelin.notebook.Folder
import org.apache.zeppelin.notebook.JobListenerFactory
import org.apache.zeppelin.notebook.Note
import org.apache.zeppelin.notebook.Notebook
import org.apache.zeppelin.notebook.NotebookAuthorization
import org.apache.zeppelin.notebook.NotebookEventListener
import org.apache.zeppelin.notebook.NotebookImportDeserializer
import org.apache.zeppelin.notebook.Paragraph
import org.apache.zeppelin.notebook.ParagraphJobListener
import org.apache.zeppelin.notebook.repo.NotebookRepoWithVersionControl.Revision
import org.apache.zeppelin.notebook.socket.Message
import org.apache.zeppelin.notebook.socket.Message.OP
import org.apache.zeppelin.notebook.socket.WatcherMessage
import org.apache.zeppelin.scheduler.Job
import org.apache.zeppelin.scheduler.Job.Status
import org.apache.zeppelin.server.ZeppelinServer
import org.apache.zeppelin.ticket.TicketContainer
import org.apache.zeppelin.types.InterpreterSettingsList
import org.apache.zeppelin.user.AuthenticationInfo
import org.apache.zeppelin.util.WatcherSecurityKey
import org.apache.zeppelin.utils.InterpreterBindingUtils
import org.apache.zeppelin.utils.SecurityUtils
import org.bitbucket.cowwoc.diffmatchpatch.DiffMatchPatch
import org.eclipse.jetty.websocket.servlet.WebSocketServlet
import org.eclipse.jetty.websocket.servlet.WebSocketServletFactory
import org.joda.time.DateTime
import org.joda.time.format.DateTimeFormat
import org.joda.time.format.DateTimeFormatter
import org.quartz.SchedulerException
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.servlet.http.HttpServletRequest
import java.io.IOException
import java.net.URISyntaxException
import java.net.UnknownHostException
import java.text.ParseException
import java.text.SimpleDateFormat
import java.util.ArrayList
import java.util.Arrays
import java.util.Collections
import java.util.Date
import java.util.HashMap
import java.util.HashSet
import java.util.LinkedList
import java.util.Queue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.regex.Matcher
import java.util.regex.Pattern

/**
 * Zeppelin websocket service.
 */
class NotebookServer : WebSocketServlet(), NotebookSocketListener, JobListenerFactory, AngularObjectRegistryListener, RemoteInterpreterProcessListener, ApplicationEventListener, NotebookServerMBean {


    private val collaborativeModeList = HashSet<String>()
    private val collaborativeModeEnable = ZeppelinConfiguration
            .create()
            .isZeppelinNotebookCollaborativeModeEnable()

    val noteSocketMap: MutableMap<String, MutableList<NotebookSocket>> = HashMap<String, MutableList<NotebookSocket>>()
    val connectedSockets: Queue<NotebookSocket> = ConcurrentLinkedQueue<NotebookSocket>()
    val userConnectedSockets: MutableMap<String, Queue<NotebookSocket>> = ConcurrentHashMap<String, Queue<NotebookSocket>>()

    private val executorService = Executors.newFixedThreadPool(10)

    /**
     * This is a special endpoint in the notebook websoket, Every connection in this Queue
     * will be able to watch every websocket event, it doesnt need to be listed into the map of
     * noteSocketMap. This can be used to get information about websocket traffic and watch what
     * is going on.
     */
    internal val watcherSockets: Queue<NotebookSocket> = Queues.newConcurrentLinkedQueue<NotebookSocket>()

    val notebookInformationListener: NotebookEventListener
        get() {
            return NotebookInformationListener(this)
        }

    public override val connectedUsers: Set<String>
        get() {
            val connectionList = Sets.newHashSet<String>()
            for (notebookSocket in connectedSockets) {
                connectionList.add(notebookSocket.user)
            }
            return connectionList
        }

    /**
     * Job manager service type.
     */
    protected enum class JobManagerService private constructor(internal val key: String) {
        JOB_MANAGER_PAGE("JOB_MANAGER_PAGE")
    }

    private fun notebook(): Notebook? {
        return ZeppelinServer.notebook
    }

    public override fun configure(factory: WebSocketServletFactory) {
        factory.setCreator(NotebookWebSocketCreator(this))
    }

    fun checkOrigin(request: HttpServletRequest, origin: String): Boolean {
        try {
            return SecurityUtils.isValidOrigin(origin, ZeppelinConfiguration.create())
        } catch (e: UnknownHostException) {
            LOG.error(e.toString(), e)
        } catch (e: URISyntaxException) {
            LOG.error(e.toString(), e)
        }

        return false
    }

    fun doWebSocketConnect(req: HttpServletRequest, protocol: String): NotebookSocket {
        return NotebookSocket(req, protocol, this)
    }

    public override fun onOpen(conn: NotebookSocket) {
        LOG.info("New connection from {} : {}", conn.request.getRemoteAddr(),
                conn.request.getRemotePort())
        connectedSockets.add(conn)
    }

    public override fun onMessage(conn: NotebookSocket, msg: String) {
        val notebook = notebook()
        try {
            val messagereceived = deserializeMessage(msg)
            LOG.debug(("RECEIVE << " + messagereceived.op +
                    ", RECEIVE PRINCIPAL << " + messagereceived.principal +
                    ", RECEIVE TICKET << " + messagereceived.ticket +
                    ", RECEIVE ROLES << " + messagereceived.roles +
                    ", RECEIVE DATA << " + messagereceived.data))

            if (LOG.isTraceEnabled()) {
                LOG.trace("RECEIVE MSG = " + messagereceived)
            }

            val ticket = TicketContainer.instance.getTicket(messagereceived.principal)
            if ((ticket != null && (messagereceived.ticket == null || ticket != messagereceived.ticket))) {
                /* not to pollute logs, log instead of exception */
                if (StringUtils.isEmpty(messagereceived.ticket)) {
                    LOG.debug("{} message: invalid ticket {} != {}", messagereceived.op,
                            messagereceived.ticket, ticket)
                } else {
                    if (messagereceived.op != OP.PING) {
                        conn.send(serializeMessage(Message(OP.SESSION_LOGOUT).put("info",
                                ("Your ticket is invalid possibly due to server restart. " + "Please login again."))))
                    }
                }
                return
            }

            val conf = ZeppelinConfiguration.create()
            val allowAnonymous = conf.isAnonymousAllowed()
            if (!allowAnonymous && messagereceived.principal == "anonymous") {
                throw Exception("Anonymous access not allowed ")
            }

            val userAndRoles = HashSet<String>()
            userAndRoles.add(messagereceived.principal)
            if (messagereceived.roles != "") {
                val roles = gson.fromJson<HashSet<String>>(messagereceived.roles, object : TypeToken<HashSet<String>>() {

                }.getType())
                if (roles != null) {
                    userAndRoles.addAll(roles)
                }
            }
            if (StringUtils.isEmpty(conn.user)) {
                addUserConnection(messagereceived.principal, conn)
            }
            val subject = AuthenticationInfo(messagereceived.principal, messagereceived.roles,
                    messagereceived.ticket)

            // Lets be elegant here
            when (messagereceived.op) {
                Message.OP.LIST_NOTES -> unicastNoteList(conn, subject, userAndRoles)
                Message.OP.RELOAD_NOTES_FROM_REPO -> broadcastReloadedNoteList(subject, userAndRoles)
                Message.OP.GET_HOME_NOTE -> sendHomeNote(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.GET_NOTE -> sendNote(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.NEW_NOTE -> createNote(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.DEL_NOTE -> removeNote(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.REMOVE_FOLDER -> removeFolder(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.MOVE_NOTE_TO_TRASH -> moveNoteToTrash(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.MOVE_FOLDER_TO_TRASH -> moveFolderToTrash(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.EMPTY_TRASH -> emptyTrash(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.RESTORE_FOLDER -> restoreFolder(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.RESTORE_NOTE -> restoreNote(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.RESTORE_ALL -> restoreAll(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.CLONE_NOTE -> cloneNote(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.IMPORT_NOTE -> importNote(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.COMMIT_PARAGRAPH -> updateParagraph(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.RUN_PARAGRAPH -> runParagraph(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.PARAGRAPH_EXECUTED_BY_SPELL -> broadcastSpellExecution(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.RUN_ALL_PARAGRAPHS -> runAllParagraphs(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.CANCEL_PARAGRAPH -> cancelParagraph(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.MOVE_PARAGRAPH -> moveParagraph(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.INSERT_PARAGRAPH -> insertParagraph(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.COPY_PARAGRAPH -> copyParagraph(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.PARAGRAPH_REMOVE -> removeParagraph(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.PARAGRAPH_CLEAR_OUTPUT -> clearParagraphOutput(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.PARAGRAPH_CLEAR_ALL_OUTPUT -> clearAllParagraphOutput(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.NOTE_UPDATE -> updateNote(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.NOTE_RENAME -> renameNote(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.FOLDER_RENAME -> renameFolder(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.UPDATE_PERSONALIZED_MODE -> updatePersonalizedMode(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.COMPLETION -> completion(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.PING -> {
                }
                Message.OP.ANGULAR_OBJECT_UPDATED -> angularObjectUpdated(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.ANGULAR_OBJECT_CLIENT_BIND -> angularObjectClientBind(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.ANGULAR_OBJECT_CLIENT_UNBIND -> angularObjectClientUnbind(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.LIST_CONFIGURATIONS -> sendAllConfigurations(conn, userAndRoles, notebook!!)
                Message.OP.CHECKPOINT_NOTE -> checkpointNote(conn, notebook!!, messagereceived)
                Message.OP.LIST_REVISION_HISTORY -> listRevisionHistory(conn, notebook!!, messagereceived)
                Message.OP.SET_NOTE_REVISION -> setNoteRevision(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.NOTE_REVISION -> getNoteByRevision(conn, notebook!!, messagereceived)
                Message.OP.NOTE_REVISION_FOR_COMPARE -> getNoteByRevisionForCompare(conn, notebook!!, messagereceived)
                Message.OP.LIST_NOTE_JOBS -> unicastNoteJobInfo(conn, messagereceived)
                Message.OP.UNSUBSCRIBE_UPDATE_NOTE_JOBS -> unsubscribeNoteJobInfo(conn)
                Message.OP.GET_INTERPRETER_BINDINGS -> getInterpreterBindings(conn, messagereceived)
                Message.OP.SAVE_INTERPRETER_BINDINGS -> saveInterpreterBindings(conn, messagereceived)
                Message.OP.EDITOR_SETTING -> getEditorSetting(conn, messagereceived)
                Message.OP.GET_INTERPRETER_SETTINGS -> getInterpreterSettings(conn, subject)
                Message.OP.WATCHER -> switchConnectionToWatcher(conn, messagereceived)
                Message.OP.SAVE_NOTE_FORMS -> saveNoteForms(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.REMOVE_NOTE_FORMS -> removeNoteForms(conn, userAndRoles, notebook!!, messagereceived)
                Message.OP.PATCH_PARAGRAPH -> patchParagraph(conn, userAndRoles, notebook!!, messagereceived)
                else -> {
                }
            }//do nothing
        } catch (e: Exception) {
            LOG.error("Can't handle message: " + msg, e)
        }

    }

    public override fun onClose(conn: NotebookSocket, code: Int, reason: String) {
        LOG.info("Closed connection to {} : {}. ({}) {}", conn.request.getRemoteAddr(),
                conn.request.getRemotePort(), code, reason)
        removeConnectionFromAllNote(conn)
        connectedSockets.remove(conn)
        removeUserConnection(conn.user, conn)
    }

    private fun removeUserConnection(user: String?, conn: NotebookSocket) {
        if (userConnectedSockets.containsKey(user)) {
            userConnectedSockets.get(user)!!.remove(conn)
        } else {
            LOG.warn("Closing connection that is absent in user connections")
        }
    }

    private fun addUserConnection(user: String, conn: NotebookSocket) {
        conn.user = user
        if (userConnectedSockets.containsKey(user)) {
            userConnectedSockets.get(user)!!.add(conn)
        } else {
            val socketQueue = ConcurrentLinkedQueue<NotebookSocket>()
            socketQueue.add(conn)
            userConnectedSockets.put(user, socketQueue)
        }
    }

    fun deserializeMessage(msg: String): Message {
        return gson.fromJson<Message>(msg, Message::class.java!!)
    }

    fun serializeMessage(m: Message): String {
        return gson.toJson(m)
    }

    private fun addConnectionToNote(noteId: String, socket: NotebookSocket) {
        synchronized(noteSocketMap) {
            removeConnectionFromAllNote(socket) // make sure a socket relates only a
            // single note.
            var socketList: MutableList<NotebookSocket>? = noteSocketMap.get(noteId)
            if (socketList == null) {
                socketList = LinkedList<NotebookSocket>()
                noteSocketMap.put(noteId, socketList)
            }
            if (!socketList!!.contains(socket)) {
                socketList!!.add(socket)
            }
            checkCollaborativeStatus(noteId, socketList)
        }
    }

    private fun removeConnectionFromNote(noteId: String, socket: NotebookSocket) {
        synchronized(noteSocketMap) {
            val socketList = noteSocketMap.get(noteId)
            if (socketList != null) {
                socketList!!.remove(socket)
            }
            checkCollaborativeStatus(noteId, socketList)
        }
    }

    private fun removeNote(noteId: String) {
        synchronized(noteSocketMap) {
            val socketList = noteSocketMap.remove(noteId)
        }
    }

    private fun removeConnectionFromAllNote(socket: NotebookSocket) {
        synchronized(noteSocketMap) {
            val keys = noteSocketMap.keys
            for (noteId in keys) {
                removeConnectionFromNote(noteId, socket)
            }
        }
    }

    private fun checkCollaborativeStatus(noteId: String, socketList: List<NotebookSocket>?) {
        if ((!collaborativeModeEnable)!!) {
            return
        }
        val collaborativeStatusNew = socketList!!.size > 1
        if (collaborativeStatusNew) {
            collaborativeModeList.add(noteId)
        } else {
            collaborativeModeList.remove(noteId)
        }

        val message = Message(OP.COLLABORATIVE_MODE_STATUS)
        message.put("status", collaborativeStatusNew)
        if (collaborativeStatusNew) {
            val userList = HashSet<String>()
            for (noteSocket in socketList!!) {
                userList.add(noteSocket.user!!)
            }
            message.put("users", userList)
        }
        broadcast(noteId, message)
    }

    private fun getOpenNoteId(socket: NotebookSocket): String? {
        var id: String? = null
        synchronized(noteSocketMap) {
            val keys = noteSocketMap.keys
            for (noteId in keys) {
                val sockets = noteSocketMap.get(noteId)
                if (sockets!!.contains(socket)) {
                    id = noteId
                }
            }
        }

        return id
    }

    private fun broadcastToNoteBindedInterpreter(interpreterGroupId: String, m: Message) {
        val notebook = notebook()
        val notes = notebook!!.getAllNotes()
        for (note in notes) {
            val ids = notebook!!.getInterpreterSettingManager()
                    .getInterpreterBinding(note.getId())
            for (id in ids) {
                if (id == interpreterGroupId) {
                    broadcast(note.getId(), m)
                }
            }
        }
    }

    fun broadcast(m: Message) {
        synchronized(connectedSockets) {
            for (ns in connectedSockets) {
                try {
                    ns.send(serializeMessage(m))
                } catch (e: IOException) {
                    LOG.error("Send error: " + m, e)
                }

            }
        }
    }

    private fun broadcast(noteId: String, m: Message) {
        var socketsToBroadcast = emptyList<NotebookSocket>()
        synchronized(noteSocketMap) {
            broadcastToWatchers(noteId, StringUtils.EMPTY, m)
            val socketLists = noteSocketMap.get(noteId)
            if (socketLists == null || socketLists!!.size == 0) {
                return
            }
            socketsToBroadcast = ArrayList<NotebookSocket>(socketLists!!)
        }
        LOG.debug("SEND >> " + m)
        for (conn in socketsToBroadcast) {
            try {
                conn.send(serializeMessage(m))
            } catch (e: IOException) {
                LOG.error("socket error", e)
            }

        }
    }

    private fun broadcastExcept(noteId: String, m: Message, exclude: NotebookSocket) {
        var socketsToBroadcast = emptyList<NotebookSocket>()
        synchronized(noteSocketMap) {
            broadcastToWatchers(noteId, StringUtils.EMPTY, m)
            val socketLists = noteSocketMap.get(noteId)
            if (socketLists == null || socketLists!!.size == 0) {
                return
            }
            socketsToBroadcast = ArrayList<NotebookSocket>(socketLists!!)
        }

        LOG.debug("SEND >> " + m)
        for (conn in socketsToBroadcast) {
            if (exclude == conn) {
                continue
            }
            try {
                conn.send(serializeMessage(m))
            } catch (e: IOException) {
                LOG.error("socket error", e)
            }

        }
    }

    private fun multicastToUser(user: String, m: Message) {
        if (!userConnectedSockets.containsKey(user)) {
            LOG.warn("Multicasting to user {} that is not in connections map", user)
            return
        }

        for (conn in userConnectedSockets.get(user)!!) {
            unicast(m, conn)
        }
    }

    private fun unicast(m: Message, conn: NotebookSocket) {
        try {
            conn.send(serializeMessage(m))
        } catch (e: IOException) {
            LOG.error("socket error", e)
        }

        broadcastToWatchers(StringUtils.EMPTY, StringUtils.EMPTY, m)
    }

    @Throws(IOException::class)
    fun unicastNoteJobInfo(conn: NotebookSocket, fromMessage: Message) {
        addConnectionToNote(JobManagerService.JOB_MANAGER_PAGE.key, conn)
        val subject = AuthenticationInfo(fromMessage.principal)
        val noteJobs = notebook()!!.getJobListByUnixTime(false, 0, subject)
        val response = HashMap<String, Any>()

        response.put("lastResponseUnixTime", System.currentTimeMillis())
        response.put("jobs", noteJobs)

        conn.send(serializeMessage(Message(OP.LIST_NOTE_JOBS).put("noteJobs", response)))
    }

    @Throws(IOException::class)
    fun broadcastUpdateNoteJobInfo(lastUpdateUnixTime: Long) {
        var noteJobs: List<Map<String, Any>>? = LinkedList<Map<String, Any>>()
        val notebookObject = notebook()
        val jobNotes: List<Map<String, Any>>?
        if (notebookObject != null) {
            jobNotes = notebook()!!.getJobListByUnixTime(false, lastUpdateUnixTime, null)
            noteJobs = if (jobNotes == null) noteJobs else jobNotes
        }

        val response = HashMap<String, Any>()
        response.put("lastResponseUnixTime", System.currentTimeMillis())
        response.put("jobs", if (noteJobs != null) noteJobs else LinkedList<Any>())

        broadcast(JobManagerService.JOB_MANAGER_PAGE.key,
                Message(OP.LIST_UPDATE_NOTE_JOBS).put("noteRunningJobs", response))
    }

    fun unsubscribeNoteJobInfo(conn: NotebookSocket) {
        removeConnectionFromNote(JobManagerService.JOB_MANAGER_PAGE.key, conn)
    }

    fun saveInterpreterBindings(conn: NotebookSocket, fromMessage: Message) {
        val noteId = fromMessage.data.get("noteId") as String
        try {
            val settingIdList = gson.fromJson<List<String>>((fromMessage.data.get("selectedSettingIds")).toString(),
                    object : TypeToken<ArrayList<String>>() {

                    }.getType())
            val subject = AuthenticationInfo(fromMessage.principal)
            notebook()!!.bindInterpretersToNote(subject.getUser(), noteId, settingIdList)
            broadcastInterpreterBindings(noteId,
                    InterpreterBindingUtils.getInterpreterBindings(notebook()!!, noteId))
        } catch (e: Exception) {
            LOG.error("Error while saving interpreter bindings", e)
        }

    }

    @Throws(IOException::class)
    fun getInterpreterBindings(conn: NotebookSocket, fromMessage: Message) {
        val noteId = fromMessage.data.get("noteId") as String
        val settingList = InterpreterBindingUtils.getInterpreterBindings(notebook()!!, noteId)
        conn.send(serializeMessage(
                Message(OP.INTERPRETER_BINDINGS).put("interpreterBindings", settingList)))
    }

    fun generateNotesInfo(needsReload: Boolean,
                          subject: AuthenticationInfo, userAndRoles: Set<String>): List<Map<String, String>> {
        val notebook = notebook()

        val conf = notebook!!.getConf()
        val homescreenNoteId = conf.getString(ConfVars.ZEPPELIN_NOTEBOOK_HOMESCREEN)
        val hideHomeScreenNotebookFromList = conf.getBoolean(ConfVars.ZEPPELIN_NOTEBOOK_HOMESCREEN_HIDE)

        if (needsReload) {
            try {
                notebook!!.reloadAllNotes(subject)
            } catch (e: IOException) {
                LOG.error("Fail to reload notes from repository", e)
            }

        }

        val notes = notebook!!.getAllNotes(userAndRoles)
        val notesInfo = LinkedList<Map<String, String>>()
        for (note in notes) {
            val info = HashMap<String, String>()

            if (hideHomeScreenNotebookFromList && note.getId() == homescreenNoteId) {
                continue
            }

            info.put("id", note.getId())
            info.put("name", note.getName())
            notesInfo.add(info)
        }

        return notesInfo
    }

    fun broadcastNote(note: Note?) {
        broadcast(note!!.getId(), Message(OP.NOTE).put("note", note))
    }

    fun broadcastInterpreterBindings(noteId: String, settingList: List<*>) {
        broadcast(noteId, Message(OP.INTERPRETER_BINDINGS).put("interpreterBindings", settingList))
    }

    fun unicastParagraph(note: Note, p: Paragraph?, user: String?) {
        if (!note.isPersonalizedMode() || p == null || user == null) {
            return
        }

        if (!userConnectedSockets.containsKey(user)) {
            LOG.warn("Failed to send unicast. user {} that is not in connections map", user)
            return
        }

        for (conn in userConnectedSockets.get(user)!!) {
            val m = Message(OP.PARAGRAPH).put("paragraph", p)
            unicast(m, conn)
        }
    }

    fun broadcastParagraph(note: Note, p: Paragraph?) {
        broadcastNoteForms(note)

        if (note.isPersonalizedMode()) {
            broadcastParagraphs(p!!.getUserParagraphMap(), p)
        } else {
            broadcast(note.getId(), Message(OP.PARAGRAPH).put("paragraph", p))
        }
    }

    fun broadcastParagraphs(userParagraphMap: Map<String, Paragraph>?,
                            defaultParagraph: Paragraph) {
        if (null != userParagraphMap) {
            for (user in userParagraphMap!!.keys) {
                multicastToUser(user,
                        Message(OP.PARAGRAPH).put("paragraph", userParagraphMap!!.get(user)))
            }
        }
    }

    private fun broadcastNewParagraph(note: Note, para: Paragraph) {
        LOG.info("Broadcasting paragraph on run call instead of note.")
        val paraIndex = note.getParagraphs().indexOf(para)
        broadcast(note.getId(),
                Message(OP.PARAGRAPH_ADDED).put("paragraph", para).put("index", paraIndex))
    }

    fun broadcastNoteList(subject: AuthenticationInfo?, userAndRoles: HashSet<String>) {
        var subject = subject
        if (subject == null) {
            subject = AuthenticationInfo(StringUtils.EMPTY)
        }
        //send first to requesting user
        val notesInfo = generateNotesInfo(false, subject, userAndRoles)
        multicastToUser(subject!!.getUser(), Message(OP.NOTES_INFO).put("notes", notesInfo))
        //to others afterwards
        broadcastNoteListExcept(notesInfo, subject)
    }

    fun unicastNoteList(conn: NotebookSocket, subject: AuthenticationInfo,
                        userAndRoles: HashSet<String>) {
        val notesInfo = generateNotesInfo(false, subject, userAndRoles)
        unicast(Message(OP.NOTES_INFO).put("notes", notesInfo), conn)
    }

    fun broadcastReloadedNoteList(subject: AuthenticationInfo?, userAndRoles: HashSet<String>?) {
        var subject = subject
        if (subject == null) {
            subject = AuthenticationInfo(StringUtils.EMPTY)
        }

        //reload and reply first to requesting user
        val notesInfo = generateNotesInfo(true, subject, userAndRoles!!)
        multicastToUser(subject!!.getUser(), Message(OP.NOTES_INFO).put("notes", notesInfo))
        //to others afterwards
        broadcastNoteListExcept(notesInfo, subject)
    }

    private fun broadcastNoteListExcept(notesInfo: List<Map<String, String>>,
                                        subject: AuthenticationInfo) {
        var notesInfo = notesInfo
        var userAndRoles: MutableSet<String>
        val authInfo = NotebookAuthorization.getInstance()
        for (user in userConnectedSockets.keys) {
            if (subject.getUser() == user) {
                continue
            }
            //reloaded already above; parameter - false
            userAndRoles = authInfo.getRoles(user)
            userAndRoles.add(user)
            notesInfo = generateNotesInfo(false, AuthenticationInfo(user), userAndRoles)
            multicastToUser(user, Message(OP.NOTES_INFO).put("notes", notesInfo))
        }
    }

    @Throws(IOException::class)
    internal fun permissionError(conn: NotebookSocket, op: String, userName: String, userAndRoles: Set<String>,
                                 allowed: Set<String>) {
        LOG.info("Cannot {}. Connection readers {}. Allowed readers {}", op, userAndRoles, allowed)

        conn.send(serializeMessage(Message(OP.AUTH_INFO).put("info",
                ("Insufficient privileges to " + op + " note.\n\n" + "Allowed users or roles: " + allowed
                        .toString() + "\n\n" + "But the user " + userName + " belongs to: " + userAndRoles
                        .toString()))))
    }

    /**
     * @return false if user doesn't have reader permission for this paragraph
     */
    @Throws(IOException::class)
    private fun hasParagraphReaderPermission(conn: NotebookSocket, notebook: Notebook,
                                             noteId: String, userAndRoles: HashSet<String>, principal: String, op: String): Boolean {
        val notebookAuthorization = notebook.getNotebookAuthorization()
        if (!notebookAuthorization.isReader(noteId, userAndRoles)) {
            permissionError(conn, op, principal, userAndRoles,
                    notebookAuthorization.getOwners(noteId))
            return false
        }

        return true
    }

    /**
     * @return false if user doesn't have runner permission for this paragraph
     */
    @Throws(IOException::class)
    private fun hasParagraphRunnerPermission(conn: NotebookSocket, notebook: Notebook,
                                             noteId: String?, userAndRoles: HashSet<String>, principal: String, op: String): Boolean {
        val notebookAuthorization = notebook.getNotebookAuthorization()
        if (!notebookAuthorization.isRunner(noteId, userAndRoles)) {
            permissionError(conn, op, principal, userAndRoles,
                    notebookAuthorization.getOwners(noteId))
            return false
        }

        return true
    }

    /**
     * @return false if user doesn't have writer permission for this paragraph
     */
    @Throws(IOException::class)
    private fun hasParagraphWriterPermission(conn: NotebookSocket, notebook: Notebook,
                                             noteId: String?, userAndRoles: HashSet<String>, principal: String, op: String): Boolean {
        val notebookAuthorization = notebook.getNotebookAuthorization()
        if (!notebookAuthorization.isWriter(noteId, userAndRoles)) {
            permissionError(conn, op, principal, userAndRoles,
                    notebookAuthorization.getOwners(noteId))
            return false
        }

        return true
    }

    /**
     * @return false if user doesn't have owner permission for this paragraph
     */
    @Throws(IOException::class)
    private fun hasParagraphOwnerPermission(conn: NotebookSocket, notebook: Notebook, noteId: String,
                                            userAndRoles: HashSet<String>, principal: String, op: String): Boolean {
        val notebookAuthorization = notebook.getNotebookAuthorization()
        if (!notebookAuthorization.isOwner(noteId, userAndRoles)) {
            permissionError(conn, op, principal, userAndRoles,
                    notebookAuthorization.getOwners(noteId))
            return false
        }

        return true
    }

    @Throws(IOException::class)
    private fun sendNote(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                         fromMessage: Message) {
        LOG.info("New operation from {} : {} : {} : {} : {}", conn.request.getRemoteAddr(),
                conn.request.getRemotePort(), fromMessage.principal, fromMessage.op,
                fromMessage.get("id"))

        val noteId = fromMessage.get("id") as String
        if (noteId == null) {
            return
        }

        val user = fromMessage.principal

        var note: Note? = notebook.getNote(noteId)

        if (note != null) {
            if (!hasParagraphReaderPermission(conn, notebook, noteId,
                            userAndRoles, fromMessage.principal, "read")) {
                return
            }

            addConnectionToNote(note!!.getId(), conn)

            if (note!!.isPersonalizedMode()) {
                note = note!!.getUserNote(user)
            }
            conn.send(serializeMessage(Message(OP.NOTE).put("note", note)))
            sendAllAngularObjects(note!!, user, conn)
        } else {
            conn.send(serializeMessage(Message(OP.NOTE).put("note", null)))
        }
    }

    @Throws(IOException::class)
    private fun sendHomeNote(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                             fromMessage: Message) {
        val noteId = notebook.getConf().getString(ConfVars.ZEPPELIN_NOTEBOOK_HOMESCREEN)
        val user = fromMessage.principal

        var note: Note? = null
        if (noteId != null) {
            note = notebook.getNote(noteId)
        }

        if (note != null) {
            if (!hasParagraphReaderPermission(conn, notebook, noteId,
                            userAndRoles, fromMessage.principal, "read")) {
                return
            }

            addConnectionToNote(note!!.getId(), conn)
            conn.send(serializeMessage(Message(OP.NOTE).put("note", note)))
            sendAllAngularObjects(note!!, user, conn)
        } else {
            removeConnectionFromAllNote(conn)
            conn.send(serializeMessage(Message(OP.NOTE).put("note", null)))
        }
    }

    @Throws(IOException::class)
    private fun updateNote(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                           fromMessage: Message) {
        val noteId = fromMessage.get("id") as String
        val name = fromMessage.get("name") as String
        val config = fromMessage.get("config") as MutableMap<String, Any>
        if (noteId == null) {
            return
        }
        if (config == null) {
            return
        }

        if (!hasParagraphWriterPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "update")) {
            return
        }

        val note = notebook.getNote(noteId)
        if (note != null) {
            if (!(note!!.getConfig().get("isZeppelinNotebookCronEnable") as Boolean)) {
                if (config!!.get("cron") != null) {
                    config!!.remove("cron")
                }
            }
            val cronUpdated = isCronUpdated(config!!, note!!.getConfig())
            note!!.setName(name)
            note!!.setConfig(config)
            if (cronUpdated) {
                notebook.refreshCron(note!!.getId())
            }

            val subject = AuthenticationInfo(fromMessage.principal)
            note!!.persist(subject)
            broadcast(note!!.getId(), Message(OP.NOTE_UPDATED).put("name", name).put("config", config)
                    .put("info", note!!.getInfo()))
            broadcastNoteList(subject, userAndRoles)
        }
    }

    @Throws(IOException::class)
    private fun updatePersonalizedMode(conn: NotebookSocket, userAndRoles: HashSet<String>,
                                       notebook: Notebook, fromMessage: Message) {
        val noteId = fromMessage.get("id") as String
        val personalized = fromMessage.get("personalized") as String
        val isPersonalized = if (personalized == "true") true else false

        if (noteId == null) {
            return
        }

        if (!hasParagraphOwnerPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "persoanlized")) {
            return
        }

        val note = notebook.getNote(noteId)
        if (note != null) {
            note!!.setPersonalizedMode(isPersonalized)
            val subject = AuthenticationInfo(fromMessage.principal)
            note!!.persist(subject)
            broadcastNote(note)
        }
    }

    @Throws(IOException::class)
    private fun renameNote(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                           fromMessage: Message, op: String = "rename") {
        val noteId = fromMessage.get("id") as String
        val name = fromMessage.get("name") as String

        if (noteId == null) {
            return
        }

        if (!hasParagraphOwnerPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "rename")) {
            return
        }

        val note = notebook.getNote(noteId)
        if (note != null) {
            note!!.setName(name)
            note!!.setCronSupported(notebook.getConf())

            val subject = AuthenticationInfo(fromMessage.principal)
            note!!.persist(subject)
            broadcastNote(note)
            broadcastNoteList(subject, userAndRoles)
        }
    }

    @Throws(IOException::class)
    private fun renameFolder(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                             fromMessage: Message, op: String = "rename") {
        val oldFolderId = fromMessage.get("id") as String
        val newFolderId = fromMessage.get("name") as String

        if (oldFolderId == null) {
            return
        }

        for (note in notebook.getNotesUnderFolder(oldFolderId)) {
            val noteId = note.getId()
            if (!hasParagraphOwnerPermission(conn, notebook, noteId,
                            userAndRoles, fromMessage.principal, op + " folder of '" + note.getName() + "'")) {
                return
            }
        }

        val oldFolder = notebook.renameFolder(oldFolderId, newFolderId)

        if (oldFolder != null) {
            val subject = AuthenticationInfo(fromMessage.principal)

            val renamedNotes = oldFolder!!.getNotesRecursively()
            for (note in renamedNotes) {
                note.persist(subject)
                broadcastNote(note)
            }

            broadcastNoteList(subject, userAndRoles)
        }
    }

    private fun isCronUpdated(configA: Map<String, Any>, configB: Map<String, Any>): Boolean {
        var cronUpdated = false
        if ((configA.get("cron") != null && configB.get("cron") != null && configA.get("cron") == configB.get("cron"))) {
            cronUpdated = true
        } else if (configA.get("cron") == null && configB.get("cron") == null) {
            cronUpdated = false
        } else if (configA.get("cron") != null || configB.get("cron") != null) {
            cronUpdated = true
        }

        return cronUpdated
    }

    @Throws(IOException::class)
    private fun createNote(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                           message: Message) {
        val subject = AuthenticationInfo(message.principal)

        try {
            val note: Note

            val defaultInterpreterId = message.get("defaultInterpreterId") as String
            if (!StringUtils.isEmpty(defaultInterpreterId)) {
                val interpreterSettingIds = LinkedList<String>()
                interpreterSettingIds.add(defaultInterpreterId)
                for (interpreterSettingId in notebook.getInterpreterSettingManager().getInterpreterSettingIds()) {
                    if (interpreterSettingId != defaultInterpreterId) {
                        interpreterSettingIds.add(interpreterSettingId)
                    }
                }
                note = notebook.createNote(interpreterSettingIds, subject)
            } else {
                note = notebook.createNote(subject)
            }

            note.addNewParagraph(subject) // it's an empty note. so add one paragraph
            if (message != null) {
                var noteName = message.get("name") as String
                if (StringUtils.isEmpty(noteName)) {
                    noteName = "Note " + note.getId()
                }
                note.setName(noteName)
                note.setCronSupported(notebook.getConf())
            }

            note.persist(subject)
            addConnectionToNote(note.getId(), conn)
            conn.send(serializeMessage(Message(OP.NEW_NOTE).put("note", note)))
        } catch (e: IOException) {
            LOG.error("Exception from createNote", e)
            conn.send(serializeMessage(Message(OP.ERROR_INFO).put("info",
                    ("Oops! There is something wrong with the notebook file system. " + "Please check the logs for more details."))))
            return
        }

        broadcastNoteList(subject, userAndRoles)
    }

    @Throws(IOException::class)
    private fun removeNote(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                           fromMessage: Message) {
        val noteId = fromMessage.get("id") as String
        if (noteId == null) {
            return
        }

        if (!hasParagraphOwnerPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "remove")) {
            return
        }

        val subject = AuthenticationInfo(fromMessage.principal)
        notebook.removeNote(noteId, subject)
        removeNote(noteId)
        broadcastNoteList(subject, userAndRoles)
    }

    @Throws(IOException::class)
    private fun removeFolder(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                             fromMessage: Message) {
        val folderId = fromMessage.get("id") as String
        if (folderId == null) {
            return
        }

        val notes = notebook.getNotesUnderFolder(folderId, userAndRoles)
        for (note in notes) {
            val noteId = note.getId()

            if (!hasParagraphOwnerPermission(conn, notebook, noteId,
                            userAndRoles, fromMessage.principal, "remove folder of '" + note.getName() + "'")) {
                return
            }
        }

        val subject = AuthenticationInfo(fromMessage.principal)
        for (note in notes) {
            notebook.removeNote(note.getId(), subject)
            removeNote(note.getId())
        }
        broadcastNoteList(subject, userAndRoles)
    }

    @Throws(SchedulerException::class, IOException::class)
    private fun moveNoteToTrash(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                                fromMessage: Message) {
        val noteId = fromMessage.get("id") as String
        if (noteId == null) {
            return
        }

        val note = notebook.getNote(noteId)

        // drop cron
        val config = note!!.getConfig()
        if (config.get("cron") != null) {
            notebook.removeCron(note!!.getId())
        }

        if (note != null && !note!!.isTrash()) {
            fromMessage.put("name", Folder.TRASH_FOLDER_ID + "/" + note!!.getName())
            renameNote(conn, userAndRoles, notebook, fromMessage, "move")
            notebook.moveNoteToTrash(note!!.getId())
        }
    }

    @Throws(SchedulerException::class, IOException::class)
    private fun moveFolderToTrash(conn: NotebookSocket, userAndRoles: HashSet<String>,
                                  notebook: Notebook, fromMessage: Message) {
        val folderId = fromMessage.get("id") as String
        if (folderId == null) {
            return
        }

        val folder = notebook.getFolder(folderId)
        if (folder != null && !folder!!.isTrash()) {
            var trashFolderId = Folder.TRASH_FOLDER_ID + "/" + folderId
            if (notebook.hasFolder(trashFolderId)) {
                val currentDate = DateTime()
                val formatter = DateTimeFormat.forPattern("yyyy-MM-dd HH:mm:ss")
                trashFolderId += Folder.TRASH_FOLDER_CONFLICT_INFIX + formatter.print(currentDate)
            }

            val noteList = folder!!.getNotesRecursively()
            for (note in noteList) {
                val config = note.getConfig()
                if (config.get("cron") != null) {
                    notebook.removeCron(note.getId())
                }
            }

            fromMessage.put("name", trashFolderId)
            renameFolder(conn, userAndRoles, notebook, fromMessage, "move")
        }
    }

    @Throws(SchedulerException::class, IOException::class)
    private fun restoreNote(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                            fromMessage: Message) {
        val noteId = fromMessage.get("id") as String

        if (noteId == null) {
            return
        }

        val note = notebook.getNote(noteId)

        //restore cron
        val config = note!!.getConfig()
        if (config.get("cron") != null) {
            notebook.refreshCron(note!!.getId())
        }

        if (note != null && note!!.isTrash()) {
            fromMessage.put("name", note!!.getName().replaceFirst((Folder.TRASH_FOLDER_ID + "/").toRegex(), ""))
            renameNote(conn, userAndRoles, notebook, fromMessage, "restore")
        }
    }

    @Throws(SchedulerException::class, IOException::class)
    private fun restoreFolder(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                              fromMessage: Message) {
        val folderId = fromMessage.get("id") as String

        if (folderId == null) {
            return
        }

        val folder = notebook.getFolder(folderId)
        if (folder != null && folder!!.isTrash()) {
            var restoreName = folder!!.getId().replaceFirst((Folder.TRASH_FOLDER_ID + "/").toRegex(), "").trim({ it <= ' ' })

            //restore cron for each paragraph
            val noteList = folder!!.getNotesRecursively()
            for (note in noteList) {
                val config = note.getConfig()
                if (config.get("cron") != null) {
                    notebook.refreshCron(note.getId())
                }
            }

            // if the folder had conflict when it had moved to trash before
            val p = Pattern.compile("\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}$")
            val m = p.matcher(restoreName)
            restoreName = m.replaceAll("").trim({ it <= ' ' })

            fromMessage.put("name", restoreName)
            renameFolder(conn, userAndRoles, notebook, fromMessage, "restore")
        }
    }

    @Throws(SchedulerException::class, IOException::class)
    private fun restoreAll(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                           fromMessage: Message) {
        val trashFolder = notebook.getFolder(Folder.TRASH_FOLDER_ID)
        if (trashFolder != null) {
            fromMessage.data = HashMap<String, Any>()
            fromMessage.put("id", Folder.TRASH_FOLDER_ID)
            fromMessage.put("name", Folder.ROOT_FOLDER_ID)
            renameFolder(conn, userAndRoles, notebook, fromMessage, "restore trash")
        }
    }

    @Throws(SchedulerException::class, IOException::class)
    private fun emptyTrash(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                           fromMessage: Message) {
        fromMessage.data = HashMap<String, Any>()
        fromMessage.put("id", Folder.TRASH_FOLDER_ID)
        removeFolder(conn, userAndRoles, notebook, fromMessage)
    }

    @Throws(IOException::class)
    private fun updateParagraph(conn: NotebookSocket, userAndRoles: HashSet<String>,
                                notebook: Notebook, fromMessage: Message) {
        val paragraphId = fromMessage.get("id") as String
        if (paragraphId == null) {
            return
        }

        val params = fromMessage.get("params") as Map<String, Any>
        val config = fromMessage.get("config") as Map<String, Any>
        var noteId = getOpenNoteId(conn)
        if (noteId == null) {
            noteId = fromMessage.get("noteId") as String
        }

        if (!hasParagraphWriterPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "write")) {
            return
        }

        val note = notebook.getNote(noteId)
        var p = note.getParagraph(paragraphId)

        p!!.settings.setParams(params)
        p!!.setConfig(config)
        p!!.setTitle(fromMessage.get("title") as String)
        p!!.setText(fromMessage.get("paragraph") as String)

        val subject = AuthenticationInfo(fromMessage.principal)
        if (note.isPersonalizedMode()) {
            p = p!!.getUserParagraph(subject.getUser())
            p!!.settings.setParams(params)
            p!!.setConfig(config)
            p!!.setTitle(fromMessage.get("title") as String)
            p!!.setText(fromMessage.get("paragraph") as String)
        }

        note.persist(subject)

        if (note.isPersonalizedMode()) {
            val userParagraphMap = note.getParagraph(paragraphId)!!.getUserParagraphMap()
            broadcastParagraphs(userParagraphMap, p)
        } else {
            broadcastParagraph(note, p)
        }
    }

    @Throws(IOException::class)
    private fun patchParagraph(conn: NotebookSocket, userAndRoles: HashSet<String>,
                               notebook: Notebook, fromMessage: Message) {
        if ((!collaborativeModeEnable)!!) {
            return
        }
        val paragraphId = fromMessage.getType<String>("id", LOG)
        if (paragraphId == null) {
            return
        }

        var noteId = getOpenNoteId(conn)
        if (noteId == null) {
            noteId = fromMessage.getType<String>("noteId", LOG)
            if (noteId == null) {
                return
            }
        }

        if (!hasParagraphWriterPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "write")) {
            return
        }

        val note = notebook.getNote(noteId)
        if (note == null) {
            return
        }
        val p = note!!.getParagraph(paragraphId)
        if (p == null) {
            return
        }

        val dmp = DiffMatchPatch()
        val patchText = fromMessage.getType<String>("patch", LOG)
        if (patchText == null) {
            return
        }

        var patches: LinkedList<DiffMatchPatch.Patch>? = null
        try {
            patches = dmp.patchFromText(patchText!!) as LinkedList<DiffMatchPatch.Patch>
        } catch (e: ClassCastException) {
            LOG.error("Failed to parse patches", e)
        }

        if (patches == null) {
            return
        }

        var paragraphText = if (p!!.getText() == null) "" else p!!.getText()
        paragraphText = dmp.patchApply(patches!!, paragraphText)[0] as String
        p!!.setText(paragraphText)
        val message = Message(OP.PATCH_PARAGRAPH).put("patch", patchText)
                .put("paragraphId", p!!.getId())
        broadcastExcept(note!!.getId(), message, conn)
    }

    @Throws(IOException::class)
    private fun cloneNote(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                          fromMessage: Message) {
        val noteId = getOpenNoteId(conn)
        val name = fromMessage.get("name") as String
        val newNote = notebook.cloneNote(noteId, name, AuthenticationInfo(fromMessage.principal))
        val subject = AuthenticationInfo(fromMessage.principal)
        addConnectionToNote(newNote.getId(), conn as NotebookSocket)
        conn.send(serializeMessage(Message(OP.NEW_NOTE).put("note", newNote)))
        broadcastNoteList(subject, userAndRoles)
    }

    @Throws(IOException::class)
    private fun clearAllParagraphOutput(conn: NotebookSocket, userAndRoles: HashSet<String>,
                                        notebook: Notebook, fromMessage: Message) {
        val noteId = fromMessage.get("id") as String
        if (StringUtils.isBlank(noteId)) {
            return
        }

        if (!hasParagraphWriterPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "clear output")) {
            return
        }

        val note = notebook.getNote(noteId)
        note.clearAllParagraphOutput()
        broadcastNote(note)
    }

    @Throws(IOException::class)
    fun importNote(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                   fromMessage: Message?): Note? {
        var note: Note? = null
        if (fromMessage != null) {
            val noteName = (fromMessage!!.get("note") as Map<*, *>).get("name") as String
            val noteJson = gson.toJson(fromMessage!!.get("note"))
            val subject: AuthenticationInfo
            if (fromMessage!!.principal != null) {
                subject = AuthenticationInfo(fromMessage!!.principal)
            } else {
                subject = AuthenticationInfo("anonymous")
            }
            note = notebook.importNote(noteJson, noteName, subject)
            note!!.persist(subject)
            broadcastNote(note)
            broadcastNoteList(subject, userAndRoles)
        }
        return note
    }

    @Throws(IOException::class)
    private fun removeParagraph(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                                fromMessage: Message) {
        val paragraphId = fromMessage.get("id") as String
        if (paragraphId == null) {
            return
        }
        val noteId = getOpenNoteId(conn)

        if (!hasParagraphWriterPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "write")) {
            return
        }

        val note = notebook.getNote(noteId)

        // Don't allow removing paragraph when there is only one paragraph in the Notebook
        if (note.getParagraphCount() > 1) {
            val subject = AuthenticationInfo(fromMessage.principal)
            val para = note.removeParagraph(subject.getUser(), paragraphId)
            note.persist(subject)
            if (para != null) {
                broadcast(note.getId(), Message(OP.PARAGRAPH_REMOVED).put("id", para!!.getId()))
            }
        }
    }

    @Throws(IOException::class)
    private fun clearParagraphOutput(conn: NotebookSocket, userAndRoles: HashSet<String>,
                                     notebook: Notebook, fromMessage: Message) {
        val paragraphId = fromMessage.get("id") as String
        if (paragraphId == null) {
            return
        }

        val noteId = getOpenNoteId(conn)
        if (!hasParagraphWriterPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "write")) {
            return
        }

        val note = notebook.getNote(noteId)
        if (note.isPersonalizedMode()) {
            val user = fromMessage.principal
            val p = note.clearPersonalizedParagraphOutput(paragraphId, user)
            unicastParagraph(note, p, user)
        } else {
            note.clearParagraphOutput(paragraphId)
            val paragraph = note.getParagraph(paragraphId)
            broadcastParagraph(note, paragraph)
        }
    }

    @Throws(IOException::class)
    private fun completion(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                           fromMessage: Message) {
        val paragraphId = fromMessage.get("id") as String
        val buffer = fromMessage.get("buf") as String
        val cursor = java.lang.Double.parseDouble(fromMessage.get("cursor").toString()).toInt()
        val resp = Message(OP.COMPLETION_LIST).put("id", paragraphId)
        if (paragraphId == null) {
            conn.send(serializeMessage(resp))
            return
        }

        val note = notebook.getNote(getOpenNoteId(conn))
        var candidates: List<InterpreterCompletion>
        try {
            candidates = note.completion(paragraphId, buffer, cursor)
        } catch (e: RuntimeException) {
            LOG.info("Fail to get completion", e)
            candidates = ArrayList<InterpreterCompletion>()
        }

        resp.put("completions", candidates)
        conn.send(serializeMessage(resp))
    }

    /**
     * When angular object updated from client.
     *
     * @param conn the web socket.
     * @param notebook the notebook.
     * @param fromMessage the message.
     */
    private fun angularObjectUpdated(conn: NotebookSocket, userAndRoles: HashSet<String>,
                                     notebook: Notebook, fromMessage: Message) {
        val noteId = fromMessage.get("noteId") as String
        val paragraphId = fromMessage.get("paragraphId") as String
        val interpreterGroupId = fromMessage.get("interpreterGroupId") as String
        val varName = fromMessage.get("name") as String
        val varValue = fromMessage.get("value")
        val user = fromMessage.principal
        var ao: AngularObject<Any>? = null
        var global = false
        // propagate change to (Remote) AngularObjectRegistry
        val note = notebook.getNote(noteId)
        if (note != null) {
            val settings = notebook.getInterpreterSettingManager().getInterpreterSettings(note!!.getId())
            for (setting in settings) {
                if (setting.getInterpreterGroup(user, note!!.getId()) == null) {
                    continue
                }
                if (interpreterGroupId == setting.getInterpreterGroup(user, note!!.getId())
                                .getId()) {
                    val angularObjectRegistry = setting.getInterpreterGroup(user, note!!.getId()).getAngularObjectRegistry()

                    // first trying to get local registry
                    ao = angularObjectRegistry.get(varName, noteId, paragraphId)
                    if (ao == null) {
                        // then try notebook scope registry
                        ao = angularObjectRegistry.get(varName, noteId, null)
                        if (ao == null) {
                            // then try global scope registry
                            ao = angularObjectRegistry.get(varName, null, null)
                            if (ao == null) {
                                LOG.warn("Object {} is not binded", varName)
                            } else {
                                // path from client -> server
                                ao!!.set(varValue, false)
                                global = true
                            }
                        } else {
                            // path from client -> server
                            ao!!.set(varValue, false)
                            global = false
                        }
                    } else {
                        ao!!.set(varValue, false)
                        global = false
                    }
                    break
                }
            }
        }

        if (global) { // broadcast change to all web session that uses related
            // interpreter.
            for (n in notebook.getAllNotes()) {
                val settings = notebook.getInterpreterSettingManager().getInterpreterSettings(note!!.getId())
                for (setting in settings) {
                    if (setting.getInterpreterGroup(user, n.getId()) == null) {
                        continue
                    }
                    if (interpreterGroupId == setting.getInterpreterGroup(user, n.getId())
                                    .getId()) {
                        val angularObjectRegistry = setting.getInterpreterGroup(user, n.getId()).getAngularObjectRegistry()
                        this.broadcastExcept(n.getId(),
                                Message(OP.ANGULAR_OBJECT_UPDATE).put("angularObject", ao)
                                        .put("interpreterGroupId", interpreterGroupId).put("noteId", n.getId())
                                        .put("paragraphId", ao!!.getParagraphId()), conn)
                    }
                }
            }
        } else { // broadcast to all web session for the note
            this.broadcastExcept(note!!.getId(),
                    Message(OP.ANGULAR_OBJECT_UPDATE).put("angularObject", ao)
                            .put("interpreterGroupId", interpreterGroupId).put("noteId", note!!.getId())
                            .put("paragraphId", ao!!.getParagraphId()), conn)
        }
    }

    /**
     * Push the given Angular variable to the target interpreter angular registry given a noteId
     * and a paragraph id.
     */
    @Throws(Exception::class)
    fun angularObjectClientBind(conn: NotebookSocket, userAndRoles: HashSet<String>,
                                notebook: Notebook, fromMessage: Message) {
        val noteId = fromMessage.getType<String>("noteId")
        val varName = fromMessage.getType<String>("name")
        val varValue = fromMessage.get("value")
        val paragraphId = fromMessage.getType<String>("paragraphId")
        val note = notebook.getNote(noteId)

        if (paragraphId == null) {
            throw IllegalArgumentException(
                    "target paragraph not specified for " + "angular value bind")
        }

        if (note != null) {
            val interpreterGroup = findInterpreterGroupForParagraph(note!!, paragraphId)

            val registry = interpreterGroup.getAngularObjectRegistry()
            if (registry is RemoteAngularObjectRegistry) {

                val remoteRegistry = registry as RemoteAngularObjectRegistry
                pushAngularObjectToRemoteRegistry(noteId, paragraphId, varName, varValue, remoteRegistry,
                        interpreterGroup.getId(), conn)

            } else {
                pushAngularObjectToLocalRepo(noteId, paragraphId, varName, varValue, registry,
                        interpreterGroup.getId(), conn)
            }
        }
    }

    /**
     * Remove the given Angular variable to the target interpreter(s) angular registry given a noteId
     * and an optional list of paragraph id(s).
     */
    @Throws(Exception::class)
    fun angularObjectClientUnbind(conn: NotebookSocket, userAndRoles: HashSet<String>,
                                  notebook: Notebook, fromMessage: Message) {
        val noteId = fromMessage.getType<String>("noteId")
        val varName = fromMessage.getType<String>("name")
        val paragraphId = fromMessage.getType<String>("paragraphId")
        val note = notebook.getNote(noteId)

        if (paragraphId == null) {
            throw IllegalArgumentException(
                    "target paragraph not specified for " + "angular value unBind")
        }

        if (note != null) {
            val interpreterGroup = findInterpreterGroupForParagraph(note!!, paragraphId)

            val registry = interpreterGroup.getAngularObjectRegistry()

            if (registry is RemoteAngularObjectRegistry) {
                val remoteRegistry = registry as RemoteAngularObjectRegistry
                removeAngularFromRemoteRegistry(noteId, paragraphId, varName, remoteRegistry,
                        interpreterGroup.getId(), conn)
            } else {
                removeAngularObjectFromLocalRepo(noteId, paragraphId, varName, registry,
                        interpreterGroup.getId(), conn)
            }
        }
    }

    @Throws(Exception::class)
    private fun findInterpreterGroupForParagraph(note: Note, paragraphId: String): InterpreterGroup {
        val paragraph = note.getParagraph(paragraphId)
        if (paragraph == null) {
            throw IllegalArgumentException("Unknown paragraph with id : " + paragraphId)
        }
        return paragraph!!.getBindedInterpreter().getInterpreterGroup()
    }

    private fun pushAngularObjectToRemoteRegistry(noteId: String, paragraphId: String, varName: String,
                                                  varValue: Any, remoteRegistry: RemoteAngularObjectRegistry, interpreterGroupId: String,
                                                  conn: NotebookSocket) {
        val ao = remoteRegistry.addAndNotifyRemoteProcess(varName, varValue, noteId, paragraphId)

        this.broadcastExcept(noteId, Message(OP.ANGULAR_OBJECT_UPDATE).put("angularObject", ao)
                .put("interpreterGroupId", interpreterGroupId).put("noteId", noteId)
                .put("paragraphId", paragraphId), conn)
    }

    private fun removeAngularFromRemoteRegistry(noteId: String, paragraphId: String, varName: String,
                                                remoteRegistry: RemoteAngularObjectRegistry, interpreterGroupId: String,
                                                conn: NotebookSocket) {
        val ao = remoteRegistry.removeAndNotifyRemoteProcess(varName, noteId, paragraphId)
        this.broadcastExcept(noteId, Message(OP.ANGULAR_OBJECT_REMOVE).put("angularObject", ao)
                .put("interpreterGroupId", interpreterGroupId).put("noteId", noteId)
                .put("paragraphId", paragraphId), conn)
    }

    private fun pushAngularObjectToLocalRepo(noteId: String, paragraphId: String, varName: String,
                                             varValue: Any, registry: AngularObjectRegistry, interpreterGroupId: String,
                                             conn: NotebookSocket) {
        var angularObject: AngularObject<Any>? = registry.get(varName, noteId, paragraphId)
        if (angularObject == null) {
            angularObject = registry.add(varName, varValue, noteId, paragraphId)
        } else {
            angularObject!!.set(varValue, true)
        }

        this.broadcastExcept(noteId,
                Message(OP.ANGULAR_OBJECT_UPDATE).put("angularObject", angularObject)
                        .put("interpreterGroupId", interpreterGroupId).put("noteId", noteId)
                        .put("paragraphId", paragraphId), conn)
    }

    private fun removeAngularObjectFromLocalRepo(noteId: String, paragraphId: String, varName: String,
                                                 registry: AngularObjectRegistry, interpreterGroupId: String, conn: NotebookSocket) {
        val removed = registry.remove(varName, noteId, paragraphId)
        if (removed != null) {
            this.broadcastExcept(noteId,
                    Message(OP.ANGULAR_OBJECT_REMOVE).put("angularObject", removed)
                            .put("interpreterGroupId", interpreterGroupId).put("noteId", noteId)
                            .put("paragraphId", paragraphId), conn)
        }
    }

    @Throws(IOException::class)
    private fun moveParagraph(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                              fromMessage: Message) {
        val paragraphId = fromMessage.get("id") as String
        if (paragraphId == null) {
            return
        }

        val newIndex = java.lang.Double.parseDouble(fromMessage.get("index").toString()).toInt()
        val noteId = getOpenNoteId(conn)
        val note = notebook.getNote(noteId)

        if (!hasParagraphWriterPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "write")) {
            return
        }

        val subject = AuthenticationInfo(fromMessage.principal)
        note.moveParagraph(paragraphId, newIndex)
        note.persist(subject)
        broadcast(note.getId(),
                Message(OP.PARAGRAPH_MOVED).put("id", paragraphId).put("index", newIndex))
    }

    @Throws(IOException::class)
    private fun insertParagraph(conn: NotebookSocket, userAndRoles: HashSet<String>,
                                notebook: Notebook, fromMessage: Message): String? {
        val index = java.lang.Double.parseDouble(fromMessage.get("index").toString()).toInt()
        val noteId = getOpenNoteId(conn)
        val note = notebook.getNote(noteId)
        val subject = AuthenticationInfo(fromMessage.principal)

        if (!hasParagraphWriterPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "write")) {
            return null
        }
        val config: Map<String, Any>
        if (fromMessage.get("config") != null) {
            config = fromMessage.get("config") as Map<String, Any>
        } else {
            config = HashMap<String, Any>()
        }

        val newPara = note.insertNewParagraph(index, subject)
        newPara.setConfig(config)
        note.persist(subject)
        broadcastNewParagraph(note, newPara)

        return newPara.getId()
    }

    @Throws(IOException::class)
    private fun copyParagraph(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                              fromMessage: Message) {
        val newParaId = insertParagraph(conn, userAndRoles, notebook, fromMessage)

        if (newParaId == null) {
            return
        }
        fromMessage.put("id", newParaId)

        updateParagraph(conn, userAndRoles, notebook, fromMessage)
    }

    @Throws(IOException::class)
    private fun cancelParagraph(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                                fromMessage: Message) {
        val paragraphId = fromMessage.get("id") as String
        if (paragraphId == null) {
            return
        }

        val noteId = getOpenNoteId(conn)

        if (!hasParagraphRunnerPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "write")) {
            return
        }

        val note = notebook.getNote(noteId)
        val p = note.getParagraph(paragraphId)
        p!!.abort()
    }

    @Throws(IOException::class)
    private fun runAllParagraphs(conn: NotebookSocket, userAndRoles: HashSet<String>,
                                 notebook: Notebook, fromMessage: Message) {
        val noteId = fromMessage.get("noteId") as String
        if (StringUtils.isBlank(noteId)) {
            return
        }

        if (!hasParagraphRunnerPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "run all paragraphs")) {
            return
        }

        val paragraphs = gson.fromJson<List<Map<String, Any>>>((fromMessage.data.get("paragraphs")).toString(),
                object : TypeToken<List<Map<String, Any>>>() {

                }.getType())

        for (raw in paragraphs) {
            val paragraphId = raw.get("id") as String
            if (paragraphId == null) {
                continue
            }

            val text = raw.get("paragraph") as String
            val title = raw.get("title") as String
            val params = raw.get("params") as Map<String, Any>
            val config = raw.get("config") as Map<String, Any>

            val note = notebook.getNote(noteId)
            val p = setParagraphUsingMessage(note, fromMessage,
                    paragraphId, text, title, params, config)

            if (p.isEnabled() && !persistAndExecuteSingleParagraph(conn, note, p, true)) {
                // stop execution when one paragraph fails.
                break
            }
        }
    }

    @Throws(IOException::class)
    private fun broadcastSpellExecution(conn: NotebookSocket, userAndRoles: HashSet<String>,
                                        notebook: Notebook, fromMessage: Message) {
        val paragraphId = fromMessage.get("id") as String
        if (paragraphId == null) {
            return
        }

        val noteId = getOpenNoteId(conn)

        if (!hasParagraphWriterPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "write")) {
            return
        }

        val text = fromMessage.get("paragraph") as String
        val title = fromMessage.get("title") as String
        val status = Status.valueOf(fromMessage.get("status") as String)
        val params = fromMessage.get("params") as Map<String, Any>
        val config = fromMessage.get("config") as Map<String, Any>

        val note = notebook.getNote(noteId)
        val p = setParagraphUsingMessage(note, fromMessage, paragraphId,
                text, title, params, config)
        p.setResult(fromMessage.get("results"))
        p.setErrorMessage(fromMessage.get("errorMessage") as String)
        p.setStatusWithoutNotification(status)

        // Spell uses ISO 8601 formatted string generated from moment
        val dateStarted = fromMessage.get("dateStarted") as String
        val dateFinished = fromMessage.get("dateFinished") as String
        val df = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSX")

        try {
            p.setDateStarted(df.parse(dateStarted))
        } catch (e: ParseException) {
            LOG.error("Failed parse dateStarted", e)
        }

        try {
            p.setDateFinished(df.parse(dateFinished))
        } catch (e: ParseException) {
            LOG.error("Failed parse dateFinished", e)
        }

        addNewParagraphIfLastParagraphIsExecuted(note, p)
        if (!persistNoteWithAuthInfo(conn, note, p)) {
            return
        }

        // broadcast to other clients only
        broadcastExcept(note.getId(),
                Message(OP.RUN_PARAGRAPH_USING_SPELL).put("paragraph", p), conn)
    }

    @Throws(IOException::class)
    private fun runParagraph(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                             fromMessage: Message) {
        val paragraphId = fromMessage.get("id") as String
        if (paragraphId == null) {
            return
        }

        val noteId = getOpenNoteId(conn)

        if (!hasParagraphRunnerPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "write")) {
            return
        }

        // 1. clear paragraph only if personalized,
        // otherwise this will be handed in `onOutputClear`
        val note = notebook.getNote(noteId)
        if (note.isPersonalizedMode()) {
            val user = fromMessage.principal
            val p = note.clearPersonalizedParagraphOutput(paragraphId, user)
            unicastParagraph(note, p, user)
        }

        // 2. set paragraph values
        val text = fromMessage.get("paragraph") as String
        val title = fromMessage.get("title") as String
        val params = fromMessage.get("params") as Map<String, Any>
        val config = fromMessage.get("config") as Map<String, Any>

        val p = setParagraphUsingMessage(note, fromMessage, paragraphId,
                text, title, params, config)

        persistAndExecuteSingleParagraph(conn, note, p, false)
    }

    private fun addNewParagraphIfLastParagraphIsExecuted(note: Note, p: Paragraph) {
        // if it's the last paragraph and not empty, let's add a new one
        val isTheLastParagraph = note.isLastParagraph(p.getId())
        if ((!((Strings.isNullOrEmpty(p.getText()) || Strings.isNullOrEmpty(p.getScriptText()))) && isTheLastParagraph)) {
            val newPara = note.addNewParagraph(p.getAuthenticationInfo())
            broadcastNewParagraph(note, newPara)
        }
    }

    /**
     * @return false if failed to save a note
     */
    @Throws(IOException::class)
    private fun persistNoteWithAuthInfo(conn: NotebookSocket, note: Note, p: Paragraph): Boolean {
        try {
            note.persist(p.getAuthenticationInfo())
            return true
        } catch (ex: IOException) {
            LOG.error("Exception from run", ex)
            conn.send(serializeMessage(Message(OP.ERROR_INFO).put("info",
                    ("Oops! There is something wrong with the notebook file system. " + "Please check the logs for more details."))))
            // don't run the paragraph when there is error on persisting the note information
            return false
        }

    }

    @Throws(IOException::class)
    private fun persistAndExecuteSingleParagraph(conn: NotebookSocket, note: Note, p: Paragraph?,
                                                 blocking: Boolean): Boolean {
        addNewParagraphIfLastParagraphIsExecuted(note, p!!)
        if (!persistNoteWithAuthInfo(conn, note, p!!)) {
            return false
        }

        try {
            return note.run(p!!.getId(), blocking)
        } catch (ex: Exception) {
            LOG.error("Exception from run", ex)
            if (p != null) {
                p!!.setReturn(InterpreterResult(InterpreterResult.Code.ERROR, ex.message), ex)
                p!!.setStatus(Status.ERROR)
                broadcast(note.getId(), Message(OP.PARAGRAPH).put("paragraph", p))
            }
            return false
        }

    }

    private fun setParagraphUsingMessage(note: Note, fromMessage: Message, paragraphId: String,
                                         text: String, title: String, params: Map<String, Any>, config: Map<String, Any>): Paragraph {
        var p = note.getParagraph(paragraphId)
        p!!.setText(text)
        p!!.setTitle(title)
        val subject = AuthenticationInfo(fromMessage.principal, fromMessage.roles, fromMessage.ticket)
        p!!.setAuthenticationInfo(subject)
        p!!.settings.setParams(params)
        p!!.setConfig(config)

        if (note.isPersonalizedMode()) {
            p = note.getParagraph(paragraphId)
            p!!.setText(text)
            p!!.setTitle(title)
            p!!.setAuthenticationInfo(subject)
            p!!.settings.setParams(params)
            p!!.setConfig(config)
        }

        return p
    }

    @Throws(IOException::class)
    private fun sendAllConfigurations(conn: NotebookSocket, userAndRoles: HashSet<String>,
                                      notebook: Notebook) {
        val conf = notebook.getConf()

        val configurations = conf.dumpConfigurations(conf, object : ZeppelinConfiguration.ConfigurationKeyPredicate {
            public override fun apply(key: String): Boolean {
                return (!key.contains("password") && key != ZeppelinConfiguration.ConfVars.ZEPPELIN_NOTEBOOK_AZURE_CONNECTION_STRING
                        .getVarName())
            }
        })
        configurations.put("isRevisionSupported", (notebook.isRevisionSupported()).toString())
        conn.send(serializeMessage(
                Message(OP.CONFIGURATIONS_INFO).put("configurations", configurations)))
    }

    @Throws(IOException::class)
    private fun checkpointNote(conn: NotebookSocket, notebook: Notebook, fromMessage: Message) {
        val noteId = fromMessage.get("noteId") as String
        val commitMessage = fromMessage.get("commitMessage") as String
        val subject = AuthenticationInfo(fromMessage.principal)
        val revision = notebook.checkpointNote(noteId, commitMessage, subject)
        if (!Revision.isEmpty(revision)) {
            val revisions = notebook.listRevisionHistory(noteId, subject)
            conn.send(
                    serializeMessage(Message(OP.LIST_REVISION_HISTORY).put("revisionList", revisions)))
        } else {
            conn.send(serializeMessage(Message(OP.ERROR_INFO).put("info",
                    ("Couldn't checkpoint note revision: possibly storage doesn't support versioning. " + "Please check the logs for more details."))))
        }
    }

    @Throws(IOException::class)
    private fun listRevisionHistory(conn: NotebookSocket, notebook: Notebook, fromMessage: Message) {
        val noteId = fromMessage.get("noteId") as String
        val subject = AuthenticationInfo(fromMessage.principal)
        val revisions = notebook.listRevisionHistory(noteId, subject)

        conn.send(
                serializeMessage(Message(OP.LIST_REVISION_HISTORY).put("revisionList", revisions)))
    }

    @Throws(IOException::class)
    private fun setNoteRevision(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                                fromMessage: Message) {
        val noteId = fromMessage.get("noteId") as String
        val revisionId = fromMessage.get("revisionId") as String
        val subject = AuthenticationInfo(fromMessage.principal)

        if (!hasParagraphWriterPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "update")) {
            return
        }

        var headNote: Note? = null
        var setRevisionStatus: Boolean
        try {
            headNote = notebook.setNoteRevision(noteId, revisionId, subject)
            setRevisionStatus = headNote != null
        } catch (e: Exception) {
            setRevisionStatus = false
            LOG.error("Failed to set given note revision", e)
        }

        if (setRevisionStatus) {
            notebook.loadNoteFromRepo(noteId, subject)
        }

        conn.send(serializeMessage(Message(OP.SET_NOTE_REVISION).put("status", setRevisionStatus)))

        if (setRevisionStatus) {
            val reloadedNote = notebook.getNote(headNote!!.getId())
            broadcastNote(reloadedNote)
        } else {
            conn.send(serializeMessage(Message(OP.ERROR_INFO).put("info",
                    ("Couldn't set note to the given revision. " + "Please check the logs for more details."))))
        }
    }

    @Throws(IOException::class)
    private fun getNoteByRevision(conn: NotebookSocket, notebook: Notebook, fromMessage: Message) {
        val noteId = fromMessage.get("noteId") as String
        val revisionId = fromMessage.get("revisionId") as String
        val subject = AuthenticationInfo(fromMessage.principal)
        val revisionNote = notebook.getNoteByRevision(noteId, revisionId, subject)
        conn.send(serializeMessage(
                Message(OP.NOTE_REVISION).put("noteId", noteId).put("revisionId", revisionId)
                        .put("note", revisionNote)))
    }

    @Throws(IOException::class)
    private fun getNoteByRevisionForCompare(conn: NotebookSocket, notebook: Notebook,
                                            fromMessage: Message) {
        val noteId = fromMessage.get("noteId") as String
        val revisionId = fromMessage.get("revisionId") as String

        val position = fromMessage.get("position") as String
        val subject = AuthenticationInfo(fromMessage.principal)
        val revisionNote: Note?
        if (revisionId == "Head") {
            revisionNote = notebook.getNote(noteId)
        } else {
            revisionNote = notebook.getNoteByRevision(noteId, revisionId, subject)
        }

        conn.send(serializeMessage(
                Message(OP.NOTE_REVISION_FOR_COMPARE).put("noteId", noteId)
                        .put("revisionId", revisionId).put("position", position).put("note", revisionNote)))
    }

    /**
     * This callback is for the paragraph that runs on ZeppelinServer.
     *
     * @param output output to append
     */
    public override fun onOutputAppend(noteId: String, paragraphId: String, index: Int, output: String) {
        val msg = Message(OP.PARAGRAPH_APPEND_OUTPUT).put("noteId", noteId)
                .put("paragraphId", paragraphId).put("index", index).put("data", output)
        broadcast(noteId, msg)
    }

    /**
     * This callback is for the paragraph that runs on ZeppelinServer.
     *
     * @param output output to update (replace)
     */
    public override fun onOutputUpdated(noteId: String, paragraphId: String, index: Int,
                                        type: InterpreterResult.Type, output: String) {
        val msg = Message(OP.PARAGRAPH_UPDATE_OUTPUT).put("noteId", noteId)
                .put("paragraphId", paragraphId).put("index", index).put("type", type).put("data", output)
        val note = notebook()!!.getNote(noteId)
        if (note.isPersonalizedMode()) {
            val user = note.getParagraph(paragraphId)!!.getUser()
            if (null != user) {
                multicastToUser(user, msg)
            }
        } else {
            broadcast(noteId, msg)
        }
    }

    /**
     * This callback is for the paragraph that runs on ZeppelinServer.
     */
    public override fun onOutputClear(noteId: String, paragraphId: String) {
        val notebook = notebook()
        val note = notebook!!.getNote(noteId)
        note.clearParagraphOutput(paragraphId)
        val paragraph = note.getParagraph(paragraphId)
        broadcastParagraph(note, paragraph)
    }

    /**
     * When application append output.
     */
    public override fun onOutputAppend(noteId: String, paragraphId: String, index: Int, appId: String,
                                       output: String) {
        val msg = Message(OP.APP_APPEND_OUTPUT).put("noteId", noteId).put("paragraphId", paragraphId)
                .put("index", index).put("appId", appId).put("data", output)
        broadcast(noteId, msg)
    }

    /**
     * When application update output.
     */
    public override fun onOutputUpdated(noteId: String, paragraphId: String, index: Int, appId: String,
                                        type: InterpreterResult.Type, output: String) {
        val msg = Message(OP.APP_UPDATE_OUTPUT).put("noteId", noteId).put("paragraphId", paragraphId)
                .put("index", index).put("type", type).put("appId", appId).put("data", output)
        broadcast(noteId, msg)
    }

    public override fun onLoad(noteId: String, paragraphId: String, appId: String, pkg: HeliumPackage) {
        val msg = Message(OP.APP_LOAD).put("noteId", noteId).put("paragraphId", paragraphId)
                .put("appId", appId).put("pkg", pkg)
        broadcast(noteId, msg)
    }

    public override fun onStatusChange(noteId: String, paragraphId: String, appId: String, status: String) {
        val msg = Message(OP.APP_STATUS_CHANGE).put("noteId", noteId).put("paragraphId", paragraphId)
                .put("appId", appId).put("status", status)
        broadcast(noteId, msg)
    }


    @Throws(IOException::class)
    public override fun runParagraphs(noteId: String,
                                      paragraphIndices: List<Int>?,
                                      paragraphIds: List<String>?,
                                      curParagraphId: String) {
        val notebook = notebook()
        val note = notebook!!.getNote(noteId)
        val toBeRunParagraphIds = ArrayList<String>()
        if (note == null) {
            throw IOException("Not existed noteId: " + noteId)
        }
        if (!paragraphIds!!.isEmpty() && !paragraphIndices!!.isEmpty()) {
            throw IOException("Can not specify paragraphIds and paragraphIndices together")
        }
        if (paragraphIds != null && !paragraphIds!!.isEmpty()) {
            for (paragraphId in paragraphIds!!) {
                if (note!!.getParagraph(paragraphId) == null) {
                    throw IOException("Not existed paragraphId: " + paragraphId)
                }
                if (paragraphId != curParagraphId) {
                    toBeRunParagraphIds.add(paragraphId)
                }
            }
        }
        if (paragraphIndices != null && !paragraphIndices!!.isEmpty()) {
            for (paragraphIndex in paragraphIndices!!) {
                if (note!!.getParagraph(paragraphIndex) == null) {
                    throw IOException("Not existed paragraphIndex: " + paragraphIndex)
                }
                if (note!!.getParagraph(paragraphIndex).getId() != curParagraphId) {
                    toBeRunParagraphIds.add(note!!.getParagraph(paragraphIndex).getId())
                }
            }
        }
        // run the whole note except the current paragraph
        if (paragraphIds!!.isEmpty() && paragraphIndices!!.isEmpty()) {
            for (paragraph in note!!.getParagraphs()) {
                if (paragraph.getId() != curParagraphId) {
                    toBeRunParagraphIds.add(paragraph.getId())
                }
            }
        }
        val runThread = object : Runnable {
            public override fun run() {
                for (paragraphId in toBeRunParagraphIds) {
                    note!!.run(paragraphId, true)
                }
            }
        }
        executorService.submit(runThread)
    }


    /**
     * Notebook Information Change event.
     */
    class NotebookInformationListener(private val notebookServer: NotebookServer) : NotebookEventListener {

        public override fun onParagraphRemove(p: Paragraph) {
            try {
                notebookServer.broadcastUpdateNoteJobInfo(System.currentTimeMillis() - 5000)
            } catch (ioe: IOException) {
                LOG.error("can not broadcast for job manager {}", ioe.message)
            }

        }

        public override fun onNoteRemove(note: Note) {
            try {
                notebookServer.broadcastUpdateNoteJobInfo(System.currentTimeMillis() - 5000)
            } catch (ioe: IOException) {
                LOG.error("can not broadcast for job manager {}", ioe.message)
            }

            val notesInfo = LinkedList<Map<String, Any>>()
            val info = HashMap<String, Any>()
            info.put("noteId", note.getId())
            // set paragraphs
            val paragraphsInfo = LinkedList<Map<String, Any>>()

            // notebook json object root information.
            info.put("isRunningJob", false)
            info.put("unixTimeLastRun", 0)
            info.put("isRemoved", true)
            info.put("paragraphs", paragraphsInfo)
            notesInfo.add(info)

            val response = HashMap<String, Any>()
            response.put("lastResponseUnixTime", System.currentTimeMillis())
            response.put("jobs", notesInfo)

            notebookServer.broadcast(JobManagerService.JOB_MANAGER_PAGE.key,
                    Message(OP.LIST_UPDATE_NOTE_JOBS).put("noteRunningJobs", response))
        }

        public override fun onParagraphCreate(p: Paragraph) {
            val notebook = notebookServer.notebook()
            val notebookJobs = notebook!!.getJobListByParagraphId(p.getId())
            val response = HashMap<String, Any>()
            response.put("lastResponseUnixTime", System.currentTimeMillis())
            response.put("jobs", notebookJobs)

            notebookServer.broadcast(JobManagerService.JOB_MANAGER_PAGE.key,
                    Message(OP.LIST_UPDATE_NOTE_JOBS).put("noteRunningJobs", response))
        }

        public override fun onNoteCreate(note: Note) {
            val notebook = notebookServer.notebook()
            val notebookJobs = notebook!!.getJobListByNoteId(note.getId())
            val response = HashMap<String, Any>()
            response.put("lastResponseUnixTime", System.currentTimeMillis())
            response.put("jobs", notebookJobs)

            notebookServer.broadcast(JobManagerService.JOB_MANAGER_PAGE.key,
                    Message(OP.LIST_UPDATE_NOTE_JOBS).put("noteRunningJobs", response))
        }

        public override fun onParagraphStatusChange(p: Paragraph, status: Status) {
            val notebook = notebookServer.notebook()
            val notebookJobs = notebook!!.getJobListByParagraphId(p.getId())

            val response = HashMap<String, Any>()
            response.put("lastResponseUnixTime", System.currentTimeMillis())
            response.put("jobs", notebookJobs)

            notebookServer.broadcast(JobManagerService.JOB_MANAGER_PAGE.key,
                    Message(OP.LIST_UPDATE_NOTE_JOBS).put("noteRunningJobs", response))
        }

        public override fun onUnbindInterpreter(note: Note, setting: InterpreterSetting) {
            val notebook = notebookServer.notebook()
            val notebookJobs = notebook!!.getJobListByNoteId(note.getId())
            val response = HashMap<String, Any>()
            response.put("lastResponseUnixTime", System.currentTimeMillis())
            response.put("jobs", notebookJobs)

            notebookServer.broadcast(JobManagerService.JOB_MANAGER_PAGE.key,
                    Message(OP.LIST_UPDATE_NOTE_JOBS).put("noteRunningJobs", response))
        }
    }

    /**
     * Need description here.
     */
    class ParagraphListenerImpl(private val notebookServer: NotebookServer, private val note: Note) : ParagraphJobListener {

        public override fun onProgressUpdate(job: Job, progress: Int) {
            notebookServer.broadcast(note.getId(),
                    Message(OP.PROGRESS).put("id", job.getId()).put("progress", progress))
        }

        public override fun onStatusChange(job: Job, before: Status, after: Status) {
            if (after == Status.ERROR) {
                if (job.getException() != null) {
                    LOG.error("Error", job.getException())
                }
            }

            if (job.isTerminated()) {
                if (job.getStatus() == Status.FINISHED) {
                    LOG.info("Job {} is finished successfully, status: {}", job.getId(), job.getStatus())
                } else {
                    LOG.warn("Job {} is finished, status: {}, exception: {}, result: {}", job.getId(),
                            job.getStatus(), job.getException(), job.getReturn())
                }

                try {
                    //TODO(khalid): may change interface for JobListener and pass subject from interpreter
                    note.persist(if (job is Paragraph) (job as Paragraph).getAuthenticationInfo() else null)
                } catch (e: IOException) {
                    LOG.error(e.toString(), e)
                }

            }
            if (job is Paragraph) {
                val p = job as Paragraph
                p.setStatusToUserParagraph(job.getStatus())
                notebookServer.broadcastParagraph(note, p)
            }
            try {
                notebookServer.broadcastUpdateNoteJobInfo(System.currentTimeMillis() - 5000)
            } catch (e: IOException) {
                LOG.error("can not broadcast for job manager {}", e)
            }

        }

        /**
         * This callback is for paragraph that runs on RemoteInterpreterProcess.
         */
        public override fun onOutputAppend(paragraph: Paragraph, idx: Int, output: String) {
            val msg = Message(OP.PARAGRAPH_APPEND_OUTPUT).put("noteId", paragraph.getNote().getId())
                    .put("paragraphId", paragraph.getId()).put("data", output)

            notebookServer.broadcast(paragraph.getNote().getId(), msg)
        }

        /**
         * This callback is for paragraph that runs on RemoteInterpreterProcess.
         */
        public override fun onOutputUpdate(paragraph: Paragraph, idx: Int, result: InterpreterResultMessage) {
            val output = result.getData()
            val msg = Message(OP.PARAGRAPH_UPDATE_OUTPUT).put("noteId", paragraph.getNote().getId())
                    .put("paragraphId", paragraph.getId()).put("data", output)

            notebookServer.broadcast(paragraph.getNote().getId(), msg)
        }

        public override fun onOutputUpdateAll(paragraph: Paragraph, msgs: List<InterpreterResultMessage>) {
            // TODO
        }
    }

    public override fun getParagraphJobListener(note: Note): ParagraphJobListener {
        return ParagraphListenerImpl(this, note)
    }

    @Throws(IOException::class)
    private fun sendAllAngularObjects(note: Note, user: String, conn: NotebookSocket) {
        val settings = notebook()!!.getInterpreterSettingManager().getInterpreterSettings(note.getId())
        if (settings == null || settings.size == 0) {
            return
        }

        for (intpSetting in settings) {
            if (intpSetting.getInterpreterGroup(user, note.getId()) == null) {
                continue
            }
            val registry = intpSetting.getInterpreterGroup(user, note.getId()).getAngularObjectRegistry()
            val objects = registry.getAllWithGlobal(note.getId())
            for (`object` in objects) {
                conn.send(serializeMessage(
                        Message(OP.ANGULAR_OBJECT_UPDATE).put("angularObject", `object`)
                                .put("interpreterGroupId",
                                        intpSetting.getInterpreterGroup(user, note.getId()).getId())
                                .put("noteId", note.getId()).put("paragraphId", `object`.getParagraphId())))
            }
        }
    }

    public override fun onAdd(interpreterGroupId: String, `object`: AngularObject<*>) {
        onUpdate(interpreterGroupId, `object`)
    }

    public override fun onUpdate(interpreterGroupId: String, `object`: AngularObject<*>) {
        val notebook = notebook()
        if (notebook == null) {
            return
        }

        val notes = notebook!!.getAllNotes()
        for (note in notes) {
            if (`object`.getNoteId() != null && note.getId() != `object`.getNoteId()) {
                continue
            }

            val intpSettings = notebook!!.getInterpreterSettingManager().getInterpreterSettings(note.getId())
            if (intpSettings.isEmpty()) {
                continue
            }

            broadcast(note.getId(), Message(OP.ANGULAR_OBJECT_UPDATE).put("angularObject", `object`)
                    .put("interpreterGroupId", interpreterGroupId).put("noteId", note.getId())
                    .put("paragraphId", `object`.getParagraphId()))
        }
    }

    public override fun onRemove(interpreterGroupId: String, name: String, noteId: String?, paragraphId: String) {
        val notebook = notebook()
        val notes = notebook!!.getAllNotes()
        for (note in notes) {
            if (noteId != null && note.getId() != noteId) {
                continue
            }

            val settingIds = notebook!!.getInterpreterSettingManager().getInterpreterBinding(note.getId())
            for (id in settingIds) {
                if (interpreterGroupId.contains(id)) {
                    broadcast(note.getId(),
                            Message(OP.ANGULAR_OBJECT_REMOVE).put("name", name).put("noteId", noteId)
                                    .put("paragraphId", paragraphId))
                    break
                }
            }
        }
    }

    @Throws(IOException::class)
    private fun getEditorSetting(conn: NotebookSocket, fromMessage: Message) {
        val paragraphId = fromMessage.get("paragraphId") as String
        val replName = fromMessage.get("magic") as String
        val noteId = getOpenNoteId(conn)
        val user = fromMessage.principal
        val resp = Message(OP.EDITOR_SETTING)
        resp.put("paragraphId", paragraphId)
        val interpreter: Interpreter

        try {
            interpreter = notebook()!!.getInterpreterFactory().getInterpreter(user, noteId, replName)
            LOG.debug("getEditorSetting for interpreter: {} for paragraph {}", replName, paragraphId)
            resp.put("editor", notebook()!!.getInterpreterSettingManager().getEditorSetting(interpreter, user, noteId, replName))
            conn.send(serializeMessage(resp))
        } catch (e: InterpreterNotFoundException) {
            LOG.warn("Fail to get interpreter: " + replName)
            return
        }

    }

    @Throws(IOException::class)
    private fun getInterpreterSettings(conn: NotebookSocket, subject: AuthenticationInfo) {
        val availableSettings = notebook()!!.getInterpreterSettingManager().get()
        conn.send(serializeMessage(
                Message(OP.INTERPRETER_SETTINGS).put("interpreterSettings", availableSettings)))
    }

    private fun switchConnectionToWatcher(conn: NotebookSocket, messagereceived: Message) {
        if (!isSessionAllowedToSwitchToWatcher(conn)) {
            LOG.error("Cannot switch this client to watcher, invalid security key")
            return
        }
        LOG.info("Going to add {} to watcher socket", conn)
        // add the connection to the watcher.
        if (watcherSockets.contains(conn)) {
            LOG.info("connection alrerady present in the watcher")
            return
        }
        watcherSockets.add(conn)

        // remove this connection from regular zeppelin ws usage.
        removeConnectionFromAllNote(conn)
        connectedSockets.remove(conn)
        removeUserConnection(conn.user, conn)
    }

    private fun isSessionAllowedToSwitchToWatcher(session: NotebookSocket): Boolean {
        val watcherSecurityKey = session.request.getHeader(WatcherSecurityKey.HTTP_HEADER)
        return !((StringUtils.isBlank(watcherSecurityKey) || watcherSecurityKey != WatcherSecurityKey.getKey()))
    }

    /**
     * Send websocket message to all connections regardless of notebook id.
     */
    private fun broadcastToAllConnections(serialized: String) {
        broadcastToAllConnectionsExcept(null, serialized)
    }

    private fun broadcastToAllConnectionsExcept(exclude: NotebookSocket?, serialized: String) {
        synchronized(connectedSockets) {
            for (conn in connectedSockets) {
                if (exclude != null && exclude == conn) {
                    continue
                }

                try {
                    conn.send(serialized)
                } catch (e: IOException) {
                    LOG.error("Cannot broadcast message to watcher", e)
                }

            }
        }
    }

    private fun broadcastToWatchers(noteId: String, subject: String, message: Message) {
        synchronized(watcherSockets) {
            for (watcher in watcherSockets) {
                try {
                    watcher.send(
                            WatcherMessage.builder(noteId).subject(subject).message(serializeMessage(message))
                                    .build().toJson())
                } catch (e: IOException) {
                    LOG.error("Cannot broadcast message to watcher", e)
                }

            }
        }
    }

    public override fun onParaInfosReceived(noteId: String, paragraphId: String,
                                            interpreterSettingId: String, metaInfos: MutableMap<String, String>) {
        val note = notebook()!!.getNote(noteId)
        if (note != null) {
            val paragraph = note!!.getParagraph(paragraphId)
            if (paragraph != null) {
                val setting = notebook()!!.getInterpreterSettingManager()
                        .get(interpreterSettingId)
                setting.addNoteToPara(noteId, paragraphId)
                val label = metaInfos.get("label")
                val tooltip = metaInfos.get("tooltip")
                val keysToRemove = Arrays.asList<String>("noteId", "paraId", "label", "tooltip")
                for (removeKey in keysToRemove) {
                    metaInfos.remove(removeKey)
                }
                paragraph!!
                        .updateRuntimeInfos(label, tooltip, metaInfos, setting.getGroup(), setting.getId())
                broadcast(
                        note!!.getId(),
                        Message(OP.PARAS_INFO).put("id", paragraphId).put("infos",
                                paragraph!!.getRuntimeInfos()))
            }
        }
    }

    fun clearParagraphRuntimeInfo(setting: InterpreterSetting) {
        val noteIdAndParaMap = setting.getNoteIdAndParaMap()
        if (noteIdAndParaMap != null && !noteIdAndParaMap!!.isEmpty()) {
            for (noteId in noteIdAndParaMap!!.keys) {
                val paraIdSet = noteIdAndParaMap!!.get(noteId)
                if (paraIdSet != null && !paraIdSet!!.isEmpty()) {
                    for (paraId in paraIdSet!!) {
                        val note = notebook()!!.getNote(noteId)
                        if (note != null) {
                            val paragraph = note!!.getParagraph(paraId)
                            if (paragraph != null) {
                                paragraph!!.clearRuntimeInfo(setting.getId())
                                broadcast(noteId, Message(OP.PARAGRAPH).put("paragraph", paragraph))
                            }
                        }
                    }
                }
            }
        }
        setting.clearNoteIdAndParaMap()
    }

    fun broadcastNoteForms(note: Note) {
        val formsSettings = GUI()
        formsSettings.setForms(note.getNoteForms())
        formsSettings.setParams(note.getNoteParams())

        broadcast(note.getId(), Message(OP.SAVE_NOTE_FORMS).put("formsData", formsSettings))
    }

    @Throws(IOException::class)
    private fun saveNoteForms(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                              fromMessage: Message) {
        val noteId = fromMessage.get("noteId") as String
        val noteParams = fromMessage.get("noteParams") as Map<String, Any>

        if (!hasParagraphWriterPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "update")) {
            return
        }

        val note = notebook.getNote(noteId)
        if (note != null) {
            note!!.setNoteParams(noteParams)

            val subject = AuthenticationInfo(fromMessage.principal)
            note!!.persist(subject)
            broadcastNoteForms(note)
        }
    }

    @Throws(IOException::class)
    private fun removeNoteForms(conn: NotebookSocket, userAndRoles: HashSet<String>, notebook: Notebook,
                                fromMessage: Message) {
        val noteId = fromMessage.get("noteId") as String
        val formName = fromMessage.get("formName") as String

        if (!hasParagraphWriterPermission(conn, notebook, noteId,
                        userAndRoles, fromMessage.principal, "update")) {
            return
        }

        val note = notebook.getNote(noteId)
        if (note != null) {
            note!!.getNoteForms().remove(formName)
            note!!.getNoteParams().remove(formName)

            val subject = AuthenticationInfo(fromMessage.principal)
            note!!.persist(subject)
            broadcastNoteForms(note)
        }
    }

    public override fun sendMessage(message: String) {
        val m = Message(OP.NOTICE)
        m.data.put("notice", message)
        broadcast(m)
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(NotebookServer::class.java!!)
        private val gson = GsonBuilder()
                .setDateFormat("yyyy-MM-dd'T'HH:mm:ssZ")
                .registerTypeAdapter(Date::class.java, NotebookImportDeserializer())
                .setPrettyPrinting()
                .registerTypeAdapterFactory(Input.TypeAdapterFactory).create()
    }
}

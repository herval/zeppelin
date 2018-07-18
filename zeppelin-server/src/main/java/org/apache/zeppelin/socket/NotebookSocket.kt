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

import org.apache.commons.lang.StringUtils
import org.eclipse.jetty.websocket.api.Session
import org.eclipse.jetty.websocket.api.WebSocketAdapter

import java.io.IOException

import javax.servlet.http.HttpServletRequest

/**
 * Notebook websocket.
 */
class NotebookSocket(val request: HttpServletRequest, val protocol: String,
                     private val listener: NotebookSocketListener) : WebSocketAdapter() {
    private var connection: Session? = null
    var user: String? = null

    init {
        this.user = StringUtils.EMPTY
    }

    override fun onWebSocketClose(closeCode: Int, message: String?) {
        listener.onClose(this, closeCode, message!!)
    }

    override fun onWebSocketConnect(connection: Session) {
        this.connection = connection
        listener.onOpen(this)
    }

    override fun onWebSocketText(message: String?) {
        listener.onMessage(this, message!!)
    }

    @Synchronized
    @Throws(IOException::class)
    fun send(serializeMessage: String) {
        connection!!.remote.sendString(serializeMessage)
    }
}

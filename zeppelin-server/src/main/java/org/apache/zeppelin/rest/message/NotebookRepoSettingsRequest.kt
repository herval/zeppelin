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
package org.apache.zeppelin.rest.message

import com.google.gson.Gson

import org.apache.commons.lang.StringUtils

import java.util.Collections

import org.apache.zeppelin.common.JsonSerializable

/**
 * Represent payload of a notebook repo settings.
 */
class NotebookRepoSettingsRequest : JsonSerializable {

    var name: String
    var settings: Map<String, String>

    val isEmpty: Boolean
        get() = this === EMPTY

    init {
        name = StringUtils.EMPTY
        settings = emptyMap()
    }

    override fun toJson(): String {
        return gson.toJson(this)
    }

    companion object {
        private val gson = Gson()

        val EMPTY = NotebookRepoSettingsRequest()

        fun isEmpty(repoSetting: NotebookRepoSettingsRequest?): Boolean {
            return repoSetting?.isEmpty ?: true
        }

        fun fromJson(json: String): NotebookRepoSettingsRequest {
            return gson.fromJson(json, NotebookRepoSettingsRequest::class.java)
        }
    }
}

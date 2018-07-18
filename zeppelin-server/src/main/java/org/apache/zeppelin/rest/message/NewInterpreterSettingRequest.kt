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

import org.apache.zeppelin.common.JsonSerializable
import org.apache.zeppelin.dep.Dependency
import org.apache.zeppelin.interpreter.InterpreterOption
import org.apache.zeppelin.interpreter.InterpreterProperty

/**
 * NewInterpreterSetting REST API request message.
 */
class NewInterpreterSettingRequest : JsonSerializable {
    val name: String? = null
    val group: String? = null

    val properties: Map<String, InterpreterProperty>? = null
    val dependencies: List<Dependency>? = null
    val option: InterpreterOption? = null

    override fun toJson(): String {
        return gson.toJson(this)
    }

    companion object {
        private val gson = Gson()

        fun fromJson(json: String): NewInterpreterSettingRequest {
            return gson.fromJson(json, NewInterpreterSettingRequest::class.java)
        }
    }
}

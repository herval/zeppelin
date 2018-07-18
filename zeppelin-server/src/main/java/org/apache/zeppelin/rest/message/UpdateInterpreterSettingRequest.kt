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
 * UpdateInterpreterSetting rest api request message.
 */
class UpdateInterpreterSettingRequest(properties: Map<String, InterpreterProperty>,
                                      dependencies: List<Dependency>, option: InterpreterOption) : JsonSerializable {

    var properties: Map<String, InterpreterProperty>
        internal set
    var dependencies: List<Dependency>
        internal set
    var option: InterpreterOption
        internal set

    init {
        this.properties = properties
        this.dependencies = dependencies
        this.option = option
    }

    override fun toJson(): String {
        return gson.toJson(this)
    }

    companion object {
        private val gson = Gson()

        fun fromJson(json: String): UpdateInterpreterSettingRequest {
            return gson.fromJson(json, UpdateInterpreterSettingRequest::class.java)
        }
    }
}

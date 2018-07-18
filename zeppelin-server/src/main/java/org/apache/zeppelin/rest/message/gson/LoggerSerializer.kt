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

package org.apache.zeppelin.rest.message.gson

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonSerializationContext
import com.google.gson.JsonSerializer
import java.lang.reflect.Type
import org.apache.commons.lang3.StringUtils
import org.apache.log4j.Category
import org.apache.log4j.Level
import org.apache.log4j.Logger

class LoggerSerializer : JsonSerializer<Logger> {

    override fun serialize(
            logger: Logger, type: Type, jsonSerializationContext: JsonSerializationContext): JsonElement {
        val jsonObject = JsonObject()
        jsonObject.addProperty("name", logger.name)
        jsonObject.addProperty("level", getLoggerLevel(logger))
        return jsonObject
    }

    private fun getLoggerLevel(logger: Category?): String {
        if (null == logger) {
            return StringUtils.EMPTY
        }
        val level = logger.level
        return level?.toString() ?: getLoggerLevel(logger.parent)
    }
}

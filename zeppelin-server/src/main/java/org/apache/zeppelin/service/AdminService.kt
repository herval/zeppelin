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

package org.apache.zeppelin.service

import java.util.Enumeration
import java.util.Spliterator
import java.util.Spliterators
import java.util.stream.Collectors
import java.util.stream.StreamSupport
import javax.ws.rs.BadRequestException
import org.apache.log4j.LogManager
import org.apache.log4j.Logger
import org.apache.zeppelin.rest.message.LoggerRequest

/** This class handles all of business logic of [org.apache.zeppelin.rest.AdminRestApi].  */
class AdminService {

    val loggers: List<org.apache.log4j.Logger>
        get() {
            val loggers = LogManager.getCurrentLoggers()
            return StreamSupport.stream<Logger>(
                    Spliterators.spliteratorUnknownSize<Logger>(
                            object : Iterator<org.apache.log4j.Logger> {
                                override fun hasNext(): Boolean {
                                    return loggers.hasMoreElements()
                                }

                                override fun next(): org.apache.log4j.Logger {
                                    return org.apache.log4j.Logger::class.java.cast(loggers.nextElement())
                                }
                            },
                            Spliterator.ORDERED),
                    false)
                    .collect(Collectors.toList<Logger>())
        }

    fun getLogger(name: String): org.apache.log4j.Logger {
        return LogManager.getLogger(name)
    }

    @Throws(BadRequestException::class)
    fun setLoggerLevel(loggerRequest: LoggerRequest) {
        try {
            Class.forName(loggerRequest.name)
        } catch (ignore: Throwable) {
            throw BadRequestException(
                    "The class of '" + loggerRequest.name + "' doesn't exists")
        }

        val logger = LogManager.getLogger(loggerRequest.name)
                ?: throw BadRequestException("The name of the logger is wrong")

        val level = org.apache.log4j.Level.toLevel(loggerRequest.level, null)
                ?: throw BadRequestException("The level of the logger is wrong")

        logger.level = level
    }
}

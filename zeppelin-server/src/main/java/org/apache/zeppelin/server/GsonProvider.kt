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

package org.apache.zeppelin.server

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.io.PrintWriter
import java.lang.reflect.Type
import javax.ws.rs.Consumes
import javax.ws.rs.Produces
import javax.ws.rs.WebApplicationException
import javax.ws.rs.core.MediaType
import javax.ws.rs.core.MultivaluedMap
import javax.ws.rs.ext.MessageBodyReader
import javax.ws.rs.ext.MessageBodyWriter
import javax.ws.rs.ext.Provider
import org.apache.log4j.Logger
import org.apache.zeppelin.rest.message.LoggerRequest
import org.apache.zeppelin.rest.message.gson.LoggerSerializer

@Provider
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
class GsonProvider<T> : MessageBodyReader<T>, MessageBodyWriter<T> {
    private val gson: Gson

    init {
        val gsonBuilder = GsonBuilder().enableComplexMapKeySerialization()
        gsonBuilder.registerTypeAdapter(Logger::class.java, LoggerSerializer())
        this.gson = gsonBuilder.create()
    }

    override fun isReadable(
            type: Class<*>, genericType: Type, annotations: Array<Annotation>, mediaType: MediaType): Boolean {
        return type == LoggerRequest::class.java // For backward compatibility
    }

    @Throws(IOException::class, WebApplicationException::class)
    override fun readFrom(
            type: Class<T>,
            genericType: Type,
            annotations: Array<Annotation>,
            mediaType: MediaType,
            httpHeaders: MultivaluedMap<String, String>,
            entityStream: InputStream): T {
        return gson.fromJson(BufferedReader(InputStreamReader(entityStream)), type)
    }

    override fun isWriteable(
            type: Class<*>, genericType: Type, annotations: Array<Annotation>, mediaType: MediaType): Boolean {
        return type != String::class.java // Keep backward compatibility
    }

    @Throws(IOException::class, WebApplicationException::class)
    override fun writeTo(
            t: T,
            type: Class<*>,
            genericType: Type,
            annotations: Array<Annotation>,
            mediaType: MediaType,
            httpHeaders: MultivaluedMap<String, Any>,
            entityStream: OutputStream) {
        PrintWriter(entityStream).use { printWriter ->
            printWriter.write(gson.toJson(t))
            printWriter.flush()
        }
    }
}

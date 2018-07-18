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

import java.util.ArrayList

import javax.ws.rs.core.NewCookie
import javax.ws.rs.core.Response.ResponseBuilder

/**
 * Json response builder.
 *
 * @param <T>
</T> */
class JsonResponse<T> {
    var code: javax.ws.rs.core.Response.Status? = null
    var message: String? = null
    var body: T? = null
    @Transient
    internal var cookies: ArrayList<NewCookie>? = null
    @Transient
    internal var pretty = false

    constructor(status: javax.ws.rs.core.Response.Status) {
        this.code = status
        this.message = null
        this.body = null
    }

    constructor(status: javax.ws.rs.core.Response.Status, message: String) {
        this.code = status
        this.message = message
        this.body = null
    }

    constructor(status: javax.ws.rs.core.Response.Status, body: T) {
        this.code = status
        this.message = null
        this.body = body
    }

    constructor(status: javax.ws.rs.core.Response.Status, message: String, body: T) {
        this.code = status
        this.message = message
        this.body = body
    }

    fun setPretty(pretty: Boolean): JsonResponse<T> {
        this.pretty = pretty
        return this
    }

    /**
     * Add cookie for building.
     *
     * @param newCookie
     * @return
     */
    fun addCookie(newCookie: NewCookie): JsonResponse<T> {
        if (cookies == null) {
            cookies = ArrayList()
        }
        cookies!!.add(newCookie)

        return this
    }

    /**
     * Add cookie for building.
     *
     * @param name
     * @param value
     * @return
     */
    fun addCookie(name: String, value: String): JsonResponse<*> {
        return addCookie(NewCookie(name, value))
    }

    override fun toString(): String {
        val gsonBuilder = GsonBuilder()
        if (pretty) {
            gsonBuilder.setPrettyPrinting()
        }
        gsonBuilder.setExclusionStrategies(JsonExclusionStrategy())
        val gson = gsonBuilder.create()
        return gson.toJson(this)
    }

    fun build(): javax.ws.rs.core.Response {
        val r = javax.ws.rs.core.Response.status(code).entity(this.toString())
        if (cookies != null) {
            for (nc in cookies!!) {
                r.cookie(nc)
            }
        }
        return r.build()
    }
}

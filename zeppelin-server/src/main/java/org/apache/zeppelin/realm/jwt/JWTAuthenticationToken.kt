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
package org.apache.zeppelin.realm.jwt

import org.apache.shiro.authc.AuthenticationToken

/**
 * Created for org.apache.zeppelin.server.
 */
class JWTAuthenticationToken(userId: Any?, var token: String?) : AuthenticationToken {
    var userId: Any? = null
        private set

    init {
        this.userId = userId
    }

    override fun getPrincipal(): Any? {
        return userId
    }

    override fun getCredentials(): Any? {
        return token
    }

    fun setUserId(userId: Long) {
        this.userId = userId
    }
}

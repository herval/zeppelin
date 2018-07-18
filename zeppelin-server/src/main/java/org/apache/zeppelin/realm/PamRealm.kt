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
package org.apache.zeppelin.realm

import org.apache.shiro.authc.AuthenticationException
import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.authc.SimpleAuthenticationInfo
import org.apache.shiro.authc.UsernamePasswordToken
import org.apache.shiro.authz.AuthorizationInfo
import org.apache.shiro.authz.SimpleAuthorizationInfo
import org.apache.shiro.realm.AuthorizingRealm
import org.apache.shiro.subject.PrincipalCollection
import org.jvnet.libpam.PAM
import org.jvnet.libpam.PAMException
import org.jvnet.libpam.UnixUser
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.util.LinkedHashSet

/**
 * An `AuthorizingRealm` based on libpam4j.
 */
class PamRealm : AuthorizingRealm() {

    var service: String? = null

    override fun doGetAuthorizationInfo(principals: PrincipalCollection): AuthorizationInfo {
        val roles = LinkedHashSet<String>()

        val user = principals.oneByType(UserPrincipal::class.java)

        if (user != null) {
            roles.addAll(user.unixUser.groups)
        }

        return SimpleAuthorizationInfo(roles)
    }

    @Throws(AuthenticationException::class)
    public override fun doGetAuthenticationInfo(token: AuthenticationToken): AuthenticationInfo {
        val userToken = token as UsernamePasswordToken
        val user: UnixUser

        try {
            user = PAM(this.service)
                    .authenticate(userToken.username, String(userToken.password))
        } catch (e: PAMException) {
            throw AuthenticationException("Authentication failed for PAM.", e)
        }

        return SimpleAuthenticationInfo(
                UserPrincipal(user),
                userToken.credentials,
                name)
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(PamRealm::class.java)
    }
}

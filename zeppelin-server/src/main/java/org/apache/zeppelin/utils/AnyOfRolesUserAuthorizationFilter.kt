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
package org.apache.zeppelin.utils

import java.io.IOException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import org.apache.shiro.subject.Subject
import org.apache.shiro.web.filter.authz.RolesAuthorizationFilter

/**
 * Allows access if current user has at least one role of the specified list.
 *
 *
 * Basically, it's the same as [RolesAuthorizationFilter] but using OR instead
 * of AND on the specified roles or user.
 */
class AnyOfRolesUserAuthorizationFilter : RolesAuthorizationFilter() {
    @Throws(IOException::class)
    override fun isAccessAllowed(request: ServletRequest, response: ServletResponse,
                                 mappedValue: Any?): Boolean {
        val subject = getSubject(request, response)
        val rolesArray = mappedValue as Array<String>?

        if (rolesArray == null || rolesArray.size == 0) {
            //no roles specified, so nothing to check - allow access.
            return true
        }

        for (roleName in rolesArray) {
            if (subject.hasRole(roleName) || subject.principal == roleName) {
                return true
            }
        }
        return false
    }
}

/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.zeppelin.realm.jwt

import java.util.Arrays
import java.util.HashMap
import java.util.StringTokenizer


/***
 *
 */
class SimplePrincipalMapper : PrincipalMapper {

    var principalMappings: HashMap<String, Array<String>>? = null
    var groupMappings: HashMap<String, Array<String>>? = null

    @Throws(PrincipalMappingException::class)
    override fun loadMappingTable(principalMapping: String, groupMapping: String) {
        if (principalMapping != null) {
            principalMappings = parseMapping(principalMapping)
            groupMappings = parseMapping(groupMapping)
        }
    }

    @Throws(PrincipalMappingException::class)
    private fun parseMapping(mappings: String?): HashMap<String, Array<String>>? {
        if (mappings == null) {
            return null
        }
        val table = HashMap<String, Array<String>>()
        try {
            val t = StringTokenizer(mappings, ";")
            if (t.hasMoreTokens()) {
                do {
                    val mapping = t.nextToken()
                    val principals = mapping.substring(0, mapping.indexOf('='))
                    val value = mapping.substring(mapping.indexOf('=') + 1)
                    val v = value.split(",".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
                    val p = principals.split(",".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
                    for (i in p.indices) {
                        table[p[i]] = v
                    }
                } while (t.hasMoreTokens())
            }
            return table
        } catch (e: Exception) {
            // do not leave table in an unknown state - clear it instead
            // no principal mapping will occur
            table.clear()
            throw PrincipalMappingException(
                    "Unable to load mappings from provided string: " + mappings
                            + " - no principal mapping will be provided.", e)
        }

    }

    /* (non-Javadoc)
   * @see org.apache.hadoop.gateway.filter.PrincipalMapper#mapPrincipal(java.lang.String)
   */
    override fun mapUserPrincipal(principalName: String): String {
        var p: Array<String>? = null
        if (principalMappings != null) {
            p = principalMappings!![principalName]
        }
        return if (p == null) {
            principalName
        } else p[0]

    }

    /* (non-Javadoc)
   * @see org.apache.hadoop.gateway.filter.PrincipalMapper#mapPrincipal(java.lang.String)
   */
    override fun mapGroupPrincipal(principalName: String): Array<String> {
        var groups: Array<String>? = null
        var wildCardGroups: Array<String>? = null

        if (groupMappings != null) {
            groups = groupMappings!![principalName]
            wildCardGroups = groupMappings!!["*"]
            if (groups != null && wildCardGroups != null) {
                groups = concat(groups, wildCardGroups)
            } else if (wildCardGroups != null) {
                return wildCardGroups
            }
        }

        return groups!!
    }

    companion object {

        /**
         * @param groups
         * @param wildCardGroups
         * @return
         */
        fun <T> concat(groups: Array<T>, wildCardGroups: Array<T>): Array<T> {
            val result = Arrays.copyOf(groups, groups.size + wildCardGroups.size)
            System.arraycopy(wildCardGroups, 0, result, groups.size, wildCardGroups.size)
            return result
        }
    }
}

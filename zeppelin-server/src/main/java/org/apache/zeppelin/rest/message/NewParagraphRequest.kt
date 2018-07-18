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

import java.util.HashMap

import org.apache.zeppelin.common.JsonSerializable

/**
 * NewParagraphRequest rest api request message
 *
 * index field will be ignored when it's used to provide initial paragraphs
 * visualization (optional) one of:
 * table,pieChart,multibarChart,stackedAreaChart,lineChart,scatterChart
 * colWidth (optional), e.g. 12.0
 */
class NewParagraphRequest : JsonSerializable {

    var title: String? = null
        internal set
    var text: String? = null
        internal set
    var index: Double? = null
        internal set
    var config: HashMap<String, Any>? = null
        internal set

    override fun toJson(): String {
        return gson.toJson(this)
    }

    companion object {
        private val gson = Gson()

        fun fromJson(json: String): NewParagraphRequest {
            return gson.fromJson(json, NewParagraphRequest::class.java)
        }
    }
}

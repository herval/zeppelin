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

import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.io.IOException
import java.net.URISyntaxException

import javax.servlet.Filter
import javax.servlet.FilterChain
import javax.servlet.FilterConfig
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.apache.zeppelin.conf.ZeppelinConfiguration
import org.apache.zeppelin.utils.SecurityUtils

/**
 * Cors filter.
 */
class CorsFilter : Filter {

    @Throws(IOException::class, ServletException::class)
    override fun doFilter(request: ServletRequest, response: ServletResponse, filterChain: FilterChain) {
        val sourceHost = (request as HttpServletRequest).getHeader("Origin")
        var origin = ""

        try {
            if (SecurityUtils.isValidOrigin(sourceHost, ZeppelinConfiguration.create())) {
                origin = sourceHost
            }
        } catch (e: URISyntaxException) {
            LOGGER.error("Exception in WebDriverManager while getWebDriver ", e)
        }

        if (request.method == "OPTIONS") {
            val resp = response as HttpServletResponse
            addCorsHeaders(resp, origin)
            return
        }

        if (response is HttpServletResponse) {
            addCorsHeaders(response, origin)
        }
        filterChain.doFilter(request, response)
    }

    private fun addCorsHeaders(response: HttpServletResponse, origin: String) {
        response.setHeader("Access-Control-Allow-Origin", origin)
        response.setHeader("Access-Control-Allow-Credentials", "true")
        response.setHeader("Access-Control-Allow-Headers", "authorization,Content-Type")
        response.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, HEAD, DELETE")

        val zeppelinConfiguration = ZeppelinConfiguration.create()
        response.setHeader("X-FRAME-OPTIONS", zeppelinConfiguration.xFrameOptions)
        if (zeppelinConfiguration.useSsl()) {
            response.setHeader("Strict-Transport-Security", zeppelinConfiguration.strictTransport)
        }
        response.setHeader("X-XSS-Protection", zeppelinConfiguration.xxssProtection)
    }

    override fun destroy() {}

    @Throws(ServletException::class)
    override fun init(filterConfig: FilterConfig) {
    }

    companion object {
        private val LOGGER = LoggerFactory.getLogger(CorsFilter::class.java)
    }
}

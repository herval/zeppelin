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

import com.google.common.collect.Lists
import com.google.common.util.concurrent.ThreadFactoryBuilder
import java.io.IOException
import java.net.MalformedURLException
import java.net.URL
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import jline.internal.Preconditions
import org.apache.commons.io.FileUtils
import org.apache.zeppelin.conf.ZeppelinConfiguration
import org.apache.zeppelin.dep.DependencyResolver
import org.apache.zeppelin.interpreter.InterpreterSettingManager
import org.apache.zeppelin.rest.message.InterpreterInstallationRequest
import org.apache.zeppelin.socket.ServiceCallback
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.sonatype.aether.RepositoryException

/**
 * This class handles all of business logic for [org.apache.zeppelin.rest.InterpreterRestApi]
 */
class InterpreterService(
        private val conf: ZeppelinConfiguration, private val interpreterSettingManager: InterpreterSettingManager) {

    @Throws(Exception::class)
    fun installInterpreter(
            request: InterpreterInstallationRequest, serviceCallback: ServiceCallback) {
        Preconditions.checkNotNull(request)
        val interpreterName = request.name
        Preconditions.checkNotNull(interpreterName)
        Preconditions.checkNotNull(request.artifact)

        val interpreterBaseDir = conf.interpreterDir
        val localRepoPath = conf.interpreterLocalRepoPath

        val dependencyResolver = DependencyResolver(localRepoPath)

        val proxyUrl = conf.zeppelinProxyUrl
        if (null != proxyUrl) {
            val proxyUser = conf.zeppelinProxyUser
            val proxyPassword = conf.zeppelinProxyPassword
            try {
                dependencyResolver.setProxy(URL(proxyUrl), proxyUser, proxyPassword)
            } catch (e: MalformedURLException) {
                // TODO(jl): Not sure if it's good to raise an exception
                throw Exception("Url is not valid format", e)
            }

        }

        // TODO(jl): Make a rule between an interpreter name and an installation directory
        val possibleInterpreterDirectories = Lists.newArrayList<String>()
        possibleInterpreterDirectories.add(interpreterName)
        if (interpreterName.startsWith(ZEPPELIN_ARTIFACT_PREFIX)) {
            possibleInterpreterDirectories.add(interpreterName.replace(ZEPPELIN_ARTIFACT_PREFIX, ""))
        } else {
            possibleInterpreterDirectories.add(ZEPPELIN_ARTIFACT_PREFIX + interpreterName)
        }

        for (pn in possibleInterpreterDirectories) {
            val testInterpreterDir = Paths.get(interpreterBaseDir, pn)
            if (Files.exists(testInterpreterDir)) {
                throw Exception("Interpreter $interpreterName already exists with $pn")
            }
        }

        val interpreterDir = Paths.get(interpreterBaseDir, interpreterName)

        try {
            Files.createDirectories(interpreterDir)
        } catch (e: Exception) {
            throw Exception("Cannot create " + interpreterDir.toString())
        }

        // It might take time to finish it
        executorService.execute { downloadInterpreter(request, dependencyResolver, interpreterDir, serviceCallback) }
    }

    fun downloadInterpreter(
            request: InterpreterInstallationRequest,
            dependencyResolver: DependencyResolver,
            interpreterDir: Path,
            serviceCallback: ServiceCallback?) {
        try {
            logger.info("Start to download a dependency: {}", request.name)
            serviceCallback?.onStart("Starting to download " + request.name + " interpreter")

            dependencyResolver.load(request.artifact, interpreterDir.toFile())
            interpreterSettingManager.refreshInterpreterTemplates()
            logger.info(
                    "Finish downloading a dependency {} into {}",
                    request.name,
                    interpreterDir.toString())
            serviceCallback?.onSuccess(request.name + " downloaded")
        } catch (e: RepositoryException) {
            logger.error("Error while downloading dependencies", e)
            try {
                FileUtils.deleteDirectory(interpreterDir.toFile())
            } catch (e1: IOException) {
                logger.error(
                        "Error while removing directory. You should handle it manually: {}",
                        interpreterDir.toString(),
                        e1)
            }

            serviceCallback?.onFailure(
                    "Error while downloading " + request.name + " as " + e.message)
        } catch (e: IOException) {
            logger.error("Error while downloading dependencies", e)
            try {
                FileUtils.deleteDirectory(interpreterDir.toFile())
            } catch (e1: IOException) {
                logger.error("Error while removing directory. You should handle it manually: {}", interpreterDir.toString(), e1)
            }

            serviceCallback?.onFailure("Error while downloading " + request.name + " as " + e.message)
        }

    }

    companion object {

        private val ZEPPELIN_ARTIFACT_PREFIX = "zeppelin-"
        private val logger = LoggerFactory.getLogger(InterpreterService::class.java)
        private val executorService = Executors.newSingleThreadExecutor(
                ThreadFactoryBuilder()
                        .setNameFormat(InterpreterService::class.java.simpleName + "-")
                        .build())
    }
}

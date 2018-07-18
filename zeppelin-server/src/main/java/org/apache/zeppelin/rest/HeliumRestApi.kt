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
package org.apache.zeppelin.rest

import com.google.gson.Gson
import com.google.gson.JsonParseException
import com.google.gson.reflect.TypeToken

import org.apache.commons.io.FileUtils
import org.apache.commons.lang3.StringUtils
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.io.File
import java.io.IOException

import javax.ws.rs.GET
import javax.ws.rs.POST
import javax.ws.rs.Path
import javax.ws.rs.PathParam
import javax.ws.rs.Produces
import javax.ws.rs.QueryParam
import javax.ws.rs.core.Response

import org.apache.zeppelin.helium.Helium
import org.apache.zeppelin.helium.HeliumPackage
import org.apache.zeppelin.helium.HeliumPackageSearchResult
import org.apache.zeppelin.helium.HeliumPackageSuggestion
import org.apache.zeppelin.notebook.Note
import org.apache.zeppelin.notebook.Notebook
import org.apache.zeppelin.notebook.Paragraph
import org.apache.zeppelin.server.JsonResponse

/**
 * Helium Rest Api.
 */
@Path("/helium")
@Produces("application/json")
class HeliumRestApi(private val helium: Helium, private val notebook: Notebook) {
    internal var logger = LoggerFactory.getLogger(HeliumRestApi::class.java)
    private val gson = Gson()

    /**
     * Get all packages info.
     */
    val allPackageInfo: Response
        @GET
        @Path("package")
        get() {
            try {
                return JsonResponse(Response.Status.OK, "", helium.allPackageInfo).build()
            } catch (e: RuntimeException) {
                logger.error(e.message, e)
                return JsonResponse<String?>(Response.Status.INTERNAL_SERVER_ERROR, e.message).build()
            }

        }

    /**
     * Get all enabled packages info.
     */
    val allEnabledPackageInfo: Response
        @GET
        @Path("enabledPackage")
        get() {
            try {
                return JsonResponse(Response.Status.OK, "", helium.allEnabledPackages).build()
            } catch (e: RuntimeException) {
                logger.error(e.message, e)
                return JsonResponse<String?>(Response.Status.INTERNAL_SERVER_ERROR, e.message).build()
            }

        }

    val allPackageConfigs: Response
        @GET
        @Path("config")
        get() {
            try {
                val config = helium.allPackageConfig
                return JsonResponse(Response.Status.OK, config).build()
            } catch (e: RuntimeException) {
                logger.error(e.message, e)
                return JsonResponse<String?>(Response.Status.INTERNAL_SERVER_ERROR, e.message).build()
            }

        }

    val visualizationPackageOrder: Response
        @GET
        @Path("order/visualization")
        get() {
            try {
                val order = helium.visualizationPackageOrder
                return JsonResponse(Response.Status.OK, order).build()
            } catch (e: RuntimeException) {
                logger.error(e.message, e)
                return JsonResponse<String?>(Response.Status.INTERNAL_SERVER_ERROR, e.message).build()
            }

        }

    /**
     * Get single package info.
     */
    @GET
    @Path("package/{packageName}")
    fun getSinglePackageInfo(@PathParam("packageName") packageName: String): Response {
        if (StringUtils.isEmpty(packageName)) {
            return JsonResponse<String>(Response.Status.BAD_REQUEST,
                    "Can't get package info for empty name").build()
        }

        try {
            return JsonResponse(
                    Response.Status.OK, "", helium.getSinglePackageInfo(packageName)).build()
        } catch (e: RuntimeException) {
            logger.error(e.message, e)
            return JsonResponse<String?>(Response.Status.INTERNAL_SERVER_ERROR, e.message).build()
        }

    }

    @GET
    @Path("suggest/{noteId}/{paragraphId}")
    fun suggest(@PathParam("noteId") noteId: String,
                @PathParam("paragraphId") paragraphId: String): Response {
        val note = notebook.getNote(noteId)
                ?: return JsonResponse<String>(Response.Status.NOT_FOUND, "Note $noteId not found").build()

        val paragraph = note.getParagraph(paragraphId)
                ?: return JsonResponse<String>(Response.Status.NOT_FOUND, "Paragraph $paragraphId not found")
                        .build()
        try {
            return JsonResponse<HeliumPackageSuggestion>(Response.Status.OK, "", helium.suggestApp(paragraph)).build()
        } catch (e: RuntimeException) {
            logger.error(e.message, e)
            return JsonResponse<String?>(Response.Status.INTERNAL_SERVER_ERROR, e.message).build()
        }

    }

    @POST
    @Path("load/{noteId}/{paragraphId}")
    fun load(@PathParam("noteId") noteId: String,
             @PathParam("paragraphId") paragraphId: String, heliumPackage: String): Response {
        val note = notebook.getNote(noteId)
                ?: return JsonResponse<String>(Response.Status.NOT_FOUND, "Note $noteId not found").build()

        val paragraph = note.getParagraph(paragraphId)
                ?: return JsonResponse<String>(Response.Status.NOT_FOUND, "Paragraph $paragraphId not found")
                        .build()
        val pkg = HeliumPackage.fromJson(heliumPackage)
        try {
            return JsonResponse<String>(Response.Status.OK, "",
                    helium.applicationFactory.loadAndRun(pkg, paragraph)).build()
        } catch (e: RuntimeException) {
            logger.error(e.message, e)
            return JsonResponse<String?>(Response.Status.INTERNAL_SERVER_ERROR, e.message).build()
        }

    }

    @GET
    @Path("bundle/load/{packageName}")
    @Produces("text/javascript")
    fun bundleLoad(@QueryParam("refresh") refresh: String?,
                   @PathParam("packageName") packageName: String): Response {
        if (StringUtils.isEmpty(packageName)) {
            return JsonResponse<String>(
                    Response.Status.BAD_REQUEST,
                    "Can't get bundle due to empty package name").build()
        }

        var psr: HeliumPackageSearchResult? = null
        val enabledPackages = helium.allEnabledPackages
        for (e in enabledPackages) {
            if (e.pkg.name == packageName) {
                psr = e
                break
            }
        }

        if (psr == null) {
            // return empty to specify
            return Response.ok().build()
        }

        try {
            val bundle: File?
            val rebuild = refresh != null && refresh == "true"
            bundle = helium.getBundle(psr.pkg, rebuild)

            if (bundle == null) {
                return Response.ok().build()
            } else {
                val stringified = FileUtils.readFileToString(bundle)
                return Response.ok(stringified).build()
            }
        } catch (e: Exception) {
            logger.error(e.message, e)
            // returning error will prevent zeppelin front-end render any notebook.
            // visualization load fail doesn't need to block notebook rendering work.
            // so it's better return ok instead of any error.
            return Response.ok("ERROR: " + e.message).build()
        }

    }

    @POST
    @Path("enable/{packageName}")
    fun enablePackage(@PathParam("packageName") packageName: String, artifact: String): Response {
        try {
            return if (helium.enable(packageName, artifact)) {
                JsonResponse<String>(Response.Status.OK).build()
            } else {
                JsonResponse<String>(Response.Status.NOT_FOUND).build()
            }
        } catch (e: IOException) {
            logger.error(e.message, e)
            return JsonResponse<String?>(Response.Status.INTERNAL_SERVER_ERROR, e.message).build()
        }

    }

    @POST
    @Path("disable/{packageName}")
    fun disablePackage(@PathParam("packageName") packageName: String): Response {
        try {
            return if (helium.disable(packageName)) {
                JsonResponse<String>(Response.Status.OK).build()
            } else {
                JsonResponse<String>(Response.Status.NOT_FOUND).build()
            }
        } catch (e: IOException) {
            logger.error(e.message, e)
            return JsonResponse<String?>(Response.Status.INTERNAL_SERVER_ERROR, e.message).build()
        }

    }

    @GET
    @Path("spell/config/{packageName}")
    fun getSpellConfigUsingMagic(@PathParam("packageName") packageName: String): Response {
        if (StringUtils.isEmpty(packageName)) {
            return JsonResponse<String>(Response.Status.BAD_REQUEST, "packageName is empty").build()
        }

        try {
            val config = helium.getSpellConfig(packageName) ?: return JsonResponse<String>(Response.Status.BAD_REQUEST,
                    "Failed to find enabled package for $packageName").build()

            return JsonResponse(Response.Status.OK, config).build()
        } catch (e: RuntimeException) {
            logger.error(e.message, e)
            return JsonResponse<String?>(Response.Status.INTERNAL_SERVER_ERROR, e.message).build()
        }

    }

    @GET
    @Path("config/{packageName}/{artifact}")
    fun getPackageConfig(@PathParam("packageName") packageName: String,
                         @PathParam("artifact") artifact: String): Response {
        if (StringUtils.isEmpty(packageName) || StringUtils.isEmpty(artifact)) {
            return JsonResponse<String>(Response.Status.BAD_REQUEST,
                    "package name or artifact is empty"
            ).build()
        }

        try {
            val config = helium.getPackageConfig(packageName, artifact)
                    ?: return JsonResponse<String>(Response.Status.BAD_REQUEST,
                            "Failed to find package for $artifact").build()

            return JsonResponse(Response.Status.OK, config).build()
        } catch (e: RuntimeException) {
            logger.error(e.message, e)
            return JsonResponse<String?>(Response.Status.INTERNAL_SERVER_ERROR, e.message).build()
        }

    }

    @POST
    @Path("config/{packageName}/{artifact}")
    fun updatePackageConfig(@PathParam("packageName") packageName: String,
                            @PathParam("artifact") artifact: String, rawConfig: String): Response {
        if (StringUtils.isEmpty(packageName) || StringUtils.isEmpty(artifact)) {
            return JsonResponse<String>(Response.Status.BAD_REQUEST,
                    "package name or artifact is empty"
            ).build()
        }

        try {
            val packageConfig = gson.fromJson<Map<String, Any>>(
                    rawConfig, object : TypeToken<Map<String, Any>>() {

            }.type)
            helium.updatePackageConfig(artifact, packageConfig)
            return JsonResponse(Response.Status.OK, packageConfig).build()
        } catch (e: JsonParseException) {
            logger.error(e.message, e)
            return JsonResponse<String?>(Response.Status.BAD_REQUEST,
                    e.message).build()
        } catch (e: IOException) {
            return JsonResponse<String?>(Response.Status.INTERNAL_SERVER_ERROR,
                    e.message).build()
        } catch (e: RuntimeException) {
            return JsonResponse<String?>(Response.Status.INTERNAL_SERVER_ERROR, e.message).build()
        }

    }

    @POST
    @Path("order/visualization")
    fun setVisualizationPackageOrder(orderedPackageNameList: String): Response {
        val orderedList = gson.fromJson<List<String>>(
                orderedPackageNameList, object : TypeToken<List<String>>() {

        }.type)
        try {
            helium.visualizationPackageOrder = orderedList
            return JsonResponse<String>(Response.Status.OK).build()
        } catch (e: IOException) {
            logger.error(e.message, e)
            return JsonResponse<String?>(Response.Status.INTERNAL_SERVER_ERROR, e.message).build()
        }

    }
}

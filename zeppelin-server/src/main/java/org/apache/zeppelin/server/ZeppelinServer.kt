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

import java.lang.management.ManagementFactory
import javax.management.InstanceAlreadyExistsException
import javax.management.MBeanRegistrationException
import javax.management.MBeanServer
import javax.management.MalformedObjectNameException
import javax.management.NotCompliantMBeanException
import javax.management.ObjectName
import org.apache.commons.lang.StringUtils
import org.apache.shiro.UnavailableSecurityManagerException
import org.apache.shiro.realm.Realm
import org.apache.shiro.realm.text.IniRealm
import org.apache.shiro.web.env.EnvironmentLoaderListener
import org.apache.shiro.web.mgt.DefaultWebSecurityManager
import org.apache.shiro.web.servlet.ShiroFilter
import org.apache.zeppelin.rest.AdminRestApi
import org.apache.zeppelin.rest.exception.WebApplicationExceptionMapper
import org.apache.zeppelin.service.AdminService
import org.eclipse.jetty.http.HttpVersion
import org.eclipse.jetty.server.HttpConfiguration
import org.eclipse.jetty.server.HttpConnectionFactory
import org.eclipse.jetty.server.SecureRequestCustomizer
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.server.ServerConnector
import org.eclipse.jetty.server.SslConnectionFactory
import org.eclipse.jetty.server.handler.ContextHandlerCollection
import org.eclipse.jetty.server.session.SessionHandler
import org.eclipse.jetty.servlet.DefaultServlet
import org.eclipse.jetty.servlet.FilterHolder
import org.eclipse.jetty.servlet.ServletContextHandler
import org.eclipse.jetty.servlet.ServletHolder
import org.eclipse.jetty.util.ssl.SslContextFactory
import org.eclipse.jetty.webapp.WebAppContext
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.io.File
import java.io.IOException
import java.util.EnumSet
import java.util.HashSet

import javax.servlet.DispatcherType
import javax.ws.rs.core.Application

import org.apache.zeppelin.conf.ZeppelinConfiguration
import org.apache.zeppelin.conf.ZeppelinConfiguration.ConfVars
import org.apache.zeppelin.helium.Helium
import org.apache.zeppelin.helium.HeliumApplicationFactory
import org.apache.zeppelin.helium.HeliumBundleFactory
import org.apache.zeppelin.interpreter.InterpreterFactory
import org.apache.zeppelin.interpreter.InterpreterOutput
import org.apache.zeppelin.interpreter.InterpreterSettingManager
import org.apache.zeppelin.notebook.Notebook
import org.apache.zeppelin.notebook.NotebookAuthorization
import org.apache.zeppelin.notebook.repo.NotebookRepoSync
import org.apache.zeppelin.rest.ConfigurationsRestApi
import org.apache.zeppelin.rest.CredentialRestApi
import org.apache.zeppelin.rest.HeliumRestApi
import org.apache.zeppelin.rest.InterpreterRestApi
import org.apache.zeppelin.rest.LoginRestApi
import org.apache.zeppelin.rest.NotebookRepoRestApi
import org.apache.zeppelin.rest.NotebookRestApi
import org.apache.zeppelin.rest.SecurityRestApi
import org.apache.zeppelin.rest.ZeppelinRestApi
import org.apache.zeppelin.scheduler.SchedulerFactory
import org.apache.zeppelin.search.LuceneSearch
import org.apache.zeppelin.search.SearchService
import org.apache.zeppelin.service.InterpreterService
import org.apache.zeppelin.socket.NotebookServer
import org.apache.zeppelin.storage.ConfigStorage
import org.apache.zeppelin.user.Credentials
import org.apache.zeppelin.utils.SecurityUtils

/**
 * Main class of Zeppelin.
 */
class ZeppelinServer @Throws(Exception::class)
constructor() : Application() {

    private val interpreterSettingManager: InterpreterSettingManager
    private val schedulerFactory: SchedulerFactory
    private val replFactory: InterpreterFactory
    private val configStorage: ConfigStorage
    private val noteSearchService: SearchService
    private val notebookRepo: NotebookRepoSync
    private val notebookAuthorization: NotebookAuthorization
    private val credentials: Credentials
    private val interpreterService: InterpreterService

    init {
        val conf = ZeppelinConfiguration.create()
        if (conf.shiroPath.length > 0) {
            try {
                val realms = (org.apache.shiro.SecurityUtils
                        .getSecurityManager() as DefaultWebSecurityManager).realms
                if (realms.size > 1) {
                    var isIniRealmEnabled: Boolean? = false
                    for (realm in realms) {
                        if (realm is IniRealm && realm.ini["users"] != null) {
                            isIniRealmEnabled = true
                            break
                        }
                    }
                    if (isIniRealmEnabled!!) {
                        throw Exception("IniRealm/password based auth mechanisms should be exclusive. " + "Consider removing [users] block from shiro.ini")
                    }
                }
            } catch (e: UnavailableSecurityManagerException) {
                LOG.error("Failed to initialise shiro configuraion", e)
            }

        }

        InterpreterOutput.limit = conf.getInt(ConfVars.ZEPPELIN_INTERPRETER_OUTPUT_LIMIT)

        val heliumApplicationFactory = HeliumApplicationFactory()
        val heliumBundleFactory: HeliumBundleFactory

        if (isBinaryPackage(conf)) {
            /* In binary package, zeppelin-web/src/app/visualization and zeppelin-web/src/app/tabledata
       * are copied to lib/node_modules/zeppelin-vis, lib/node_modules/zeppelin-tabledata directory.
       * Check zeppelin/zeppelin-distribution/src/assemble/distribution.xml to see how they're
       * packaged into binary package.
       */
            heliumBundleFactory = HeliumBundleFactory(
                    conf, null,
                    File(conf.getRelativeDir(ConfVars.ZEPPELIN_DEP_LOCALREPO)),
                    File(conf.getRelativeDir("lib/node_modules/zeppelin-tabledata")!!),
                    File(conf.getRelativeDir("lib/node_modules/zeppelin-vis")!!),
                    File(conf.getRelativeDir("lib/node_modules/zeppelin-spell")!!))
        } else {
            heliumBundleFactory = HeliumBundleFactory(
                    conf, null,
                    File(conf.getRelativeDir(ConfVars.ZEPPELIN_DEP_LOCALREPO)),
                    File(conf.getRelativeDir("zeppelin-web/src/app/tabledata")!!),
                    File(conf.getRelativeDir("zeppelin-web/src/app/visualization")!!),
                    File(conf.getRelativeDir("zeppelin-web/src/app/spell")!!))
        }

        this.schedulerFactory = SchedulerFactory.singleton()
        this.interpreterSettingManager = InterpreterSettingManager(conf, notebookWsServer,
                notebookWsServer, notebookWsServer)
        this.replFactory = InterpreterFactory(interpreterSettingManager)
        this.notebookRepo = NotebookRepoSync(conf)
        this.noteSearchService = LuceneSearch(conf)
        this.notebookAuthorization = NotebookAuthorization.getInstance()
        this.credentials = Credentials(
                conf.credentialsPersist(),
                conf.credentialsPath,
                conf.credentialsEncryptKey)
        notebook = Notebook(conf,
                notebookRepo, schedulerFactory, replFactory, interpreterSettingManager, notebookWsServer,
                noteSearchService, notebookAuthorization, credentials)
        this.configStorage = ConfigStorage.getInstance(conf)

        ZeppelinServer.helium = Helium(
                conf.heliumConfPath,
                conf.heliumRegistry,
                File(conf.getRelativeDir(ConfVars.ZEPPELIN_DEP_LOCALREPO),
                        "helium-registry-cache"),
                heliumBundleFactory,
                heliumApplicationFactory,
                interpreterSettingManager)

        // create bundle
        try {
            heliumBundleFactory.buildAllPackages(helium!!.bundlePackagesToBundle)
        } catch (e: Exception) {
            LOG.error(e.message, e)
        }

        // to update notebook from application event from remote process.
        heliumApplicationFactory.notebook = notebook
        // to update fire websocket event on application event.
        heliumApplicationFactory.applicationEventListener = notebookWsServer

        notebook!!.addNotebookEventListener(heliumApplicationFactory)
        notebook!!.addNotebookEventListener(notebookWsServer!!.notebookInformationListener)
        this.interpreterService = InterpreterService(conf, interpreterSettingManager)

        // Register MBean
        if ("true" == System.getenv("ZEPPELIN_ENABLE_JMX")) {
            val mBeanServer = ManagementFactory.getPlatformMBeanServer()
            try {
                mBeanServer.registerMBean(
                        notebookWsServer,
                        ObjectName("org.apache.zeppelin:type=" + NotebookServer::class.java.simpleName))
                mBeanServer.registerMBean(
                        interpreterSettingManager,
                        ObjectName(
                                "org.apache.zeppelin:type=" + InterpreterSettingManager::class.java.simpleName))
            } catch (e: InstanceAlreadyExistsException) {
                LOG.error("Failed to register MBeans", e)
            } catch (e: MBeanRegistrationException) {
                LOG.error("Failed to register MBeans", e)
            } catch (e: MalformedObjectNameException) {
                LOG.error("Failed to register MBeans", e)
            } catch (e: NotCompliantMBeanException) {
                LOG.error("Failed to register MBeans", e)
            }

        }
    }

    override fun getClasses(): Set<Class<*>> {
        val classes = HashSet<Class<*>>()

        classes.add(GsonProvider::class.java)

        classes.add(WebApplicationExceptionMapper::class.java)

        return classes
    }

    override fun getSingletons(): Set<Any> {
        val singletons = HashSet<Any>()

        /* Rest-api root endpoint */
        val root = ZeppelinRestApi()
        singletons.add(root)

        val notebookApi = NotebookRestApi(notebook!!, notebookWsServer!!,
                noteSearchService)
        singletons.add(notebookApi)

        val notebookRepoApi = NotebookRepoRestApi(notebookRepo, notebookWsServer!!)
        singletons.add(notebookRepoApi)

        val heliumApi = HeliumRestApi(helium!!, notebook!!)
        singletons.add(heliumApi)

        val interpreterApi = InterpreterRestApi(interpreterService,
                interpreterSettingManager, notebookWsServer!!)
        singletons.add(interpreterApi)

        val credentialApi = CredentialRestApi(credentials)
        singletons.add(credentialApi)

        val securityApi = SecurityRestApi()
        singletons.add(securityApi)

        val loginRestApi = LoginRestApi()
        singletons.add(loginRestApi)

        val settingsApi = ConfigurationsRestApi(notebook!!)
        singletons.add(settingsApi)

        val adminService = AdminService()

        val adminRestApi = AdminRestApi(adminService)
        singletons.add(adminRestApi)

        return singletons
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(ZeppelinServer::class.java)

        var notebook: Notebook? = null
        var jettyWebServer: Server? = null
        var notebookWsServer: NotebookServer? = null
        var helium: Helium? = null

        @Throws(InterruptedException::class)
        @JvmStatic
        fun main(args: Array<String>) {
            val conf = ZeppelinConfiguration.create()
            conf.setProperty("args", args)

            jettyWebServer = setupJettyServer(conf)

            val contexts = ContextHandlerCollection()
            jettyWebServer!!.handler = contexts

            // Web UI
            val webApp = setupWebAppContext(contexts, conf)

            // Create `ZeppelinServer` using reflection and setup REST Api
            setupRestApiContextHandler(webApp, conf)

            // Notebook server
            setupNotebookServer(webApp, conf)

            //Below is commented since zeppelin-docs module is removed.
            //final WebAppContext webAppSwagg = setupWebAppSwagger(conf);

            LOG.info("Starting zeppelin server")
            try {
                jettyWebServer?.start() //Instantiates ZeppelinServer
                if (conf.jettyName != null) {
                    org.eclipse.jetty.http.HttpGenerator.setJettyVersion(conf.jettyName)
                }
            } catch (e: Exception) {
                LOG.error("Error while running jettyServer", e)
                System.exit(-1)
            }

            LOG.info("Done, zeppelin server started")

            Runtime.getRuntime().addShutdownHook(object : Thread() {
                override fun run() {
                    LOG.info("Shutting down Zeppelin Server ... ")
                    try {
                        jettyWebServer!!.stop()
                        if (!conf.isRecoveryEnabled) {
                            ZeppelinServer.notebook!!.interpreterSettingManager.close()
                        }
                        notebook!!.close()
                        Thread.sleep(3000)
                    } catch (e: Exception) {
                        LOG.error("Error while stopping servlet container", e)
                    }

                    LOG.info("Bye")
                }
            })

            // when zeppelin is started inside of ide (especially for eclipse)
            // for graceful shutdown, input any key in console window
            if (System.getenv("ZEPPELIN_IDENT_STRING") == null) {
                try {
                    System.`in`.read()
                } catch (e: IOException) {
                    LOG.error("Exception in ZeppelinServer while main ", e)
                }

                System.exit(0)
            }

            jettyWebServer!!.join()
            if (!conf.isRecoveryEnabled) {
                ZeppelinServer.notebook!!.interpreterSettingManager.close()
            }
        }

        private fun setupJettyServer(conf: ZeppelinConfiguration): Server {
            val server = Server()
            val connector: ServerConnector

            if (conf.useSsl()) {
                LOG.debug("Enabling SSL for Zeppelin Server on port " + conf.serverSslPort)
                val httpConfig = HttpConfiguration()
                httpConfig.secureScheme = "https"
                httpConfig.securePort = conf.serverSslPort
                httpConfig.outputBufferSize = 32768
                httpConfig.responseHeaderSize = 8192
                httpConfig.sendServerVersion = true

                val httpsConfig = HttpConfiguration(httpConfig)
                val src = SecureRequestCustomizer()
                // Only with Jetty 9.3.x
                // src.setStsMaxAge(2000);
                // src.setStsIncludeSubDomains(true);
                httpsConfig.addCustomizer(src)

                connector = ServerConnector(
                        server,
                        SslConnectionFactory(getSslContextFactory(conf), HttpVersion.HTTP_1_1.asString()),
                        HttpConnectionFactory(httpsConfig))
            } else {
                connector = ServerConnector(server)
            }

            configureRequestHeaderSize(conf, connector)
            // Set some timeout options to make debugging easier.
            val timeout = 1000 * 30
            connector.idleTimeout = timeout.toLong()
            connector.soLingerTime = -1
            connector.host = conf.serverAddress
            if (conf.useSsl()) {
                connector.port = conf.serverSslPort
            } else {
                connector.port = conf.serverPort
            }

            server.addConnector(connector)

            return server
        }

        private fun configureRequestHeaderSize(conf: ZeppelinConfiguration,
                                               connector: ServerConnector) {
            val cf = connector.getConnectionFactory(HttpVersion.HTTP_1_1.toString()) as HttpConnectionFactory
            val requestHeaderSize = conf.jettyRequestHeaderSize!!
            cf.httpConfiguration.requestHeaderSize = requestHeaderSize
        }

        private fun setupNotebookServer(webapp: WebAppContext, conf: ZeppelinConfiguration) {
            notebookWsServer = NotebookServer()
            val maxTextMessageSize = conf.websocketMaxTextMessageSize
            val servletHolder = ServletHolder(notebookWsServer)
            servletHolder.setInitParameter("maxTextMessageSize", maxTextMessageSize)

            val context = ServletContextHandler(
                    ServletContextHandler.SESSIONS)

            webapp.addServlet(servletHolder, "/ws/*")
        }

        private fun getSslContextFactory(conf: ZeppelinConfiguration): SslContextFactory {
            val sslContextFactory = SslContextFactory()

            // Set keystore
            sslContextFactory.keyStorePath = conf.keyStorePath
            sslContextFactory.keyStoreType = conf.keyStoreType
            sslContextFactory.setKeyStorePassword(conf.keyStorePassword)
            sslContextFactory.setKeyManagerPassword(conf.keyManagerPassword)

            if (conf.useClientAuth()) {
                sslContextFactory.needClientAuth = conf.useClientAuth()

                // Set truststore
                sslContextFactory.setTrustStorePath(conf.trustStorePath)
                sslContextFactory.trustStoreType = conf.trustStoreType
                sslContextFactory.setTrustStorePassword(conf.trustStorePassword)
            }

            return sslContextFactory
        }

        private fun setupRestApiContextHandler(webapp: WebAppContext, conf: ZeppelinConfiguration) {
            val servletHolder = ServletHolder(
                    org.glassfish.jersey.servlet.ServletContainer())

            servletHolder.setInitParameter("javax.ws.rs.Application", ZeppelinServer::class.java.name)
            servletHolder.name = "rest"
            servletHolder.forcedPath = "rest"

            webapp.sessionHandler = SessionHandler()
            webapp.addServlet(servletHolder, "/api/*")

            val shiroIniPath = conf.shiroPath
            if (!StringUtils.isBlank(shiroIniPath)) {
                webapp.setInitParameter("shiroConfigLocations", File(shiroIniPath).toURI().toString())
                SecurityUtils.setIsEnabled(true)
                webapp.addFilter(ShiroFilter::class.java, "/api/*", EnumSet.allOf(DispatcherType::class.java))
                        .setInitParameter("staticSecurityManagerEnabled", "true")
                webapp.addEventListener(EnvironmentLoaderListener())
            }
        }

        private fun setupWebAppContext(contexts: ContextHandlerCollection,
                                       conf: ZeppelinConfiguration): WebAppContext {
            val webApp = WebAppContext()
            webApp.contextPath = conf.serverContextPath
            val warPath = File(conf.getString(ConfVars.ZEPPELIN_WAR))
            if (warPath.isDirectory) {
                // Development mode, read from FS
                // webApp.setDescriptor(warPath+"/WEB-INF/web.xml");
                webApp.resourceBase = warPath.path
                webApp.isParentLoaderPriority = true
            } else {
                // use packaged WAR
                webApp.war = warPath.absolutePath
                val warTempDirectory = File(conf.getRelativeDir(ConfVars.ZEPPELIN_WAR_TEMPDIR))
                warTempDirectory.mkdir()
                LOG.info("ZeppelinServer Webapp path: {}", warTempDirectory.path)
                webApp.tempDirectory = warTempDirectory
            }
            // Explicit bind to root
            webApp.addServlet(ServletHolder(DefaultServlet()), "/*")
            contexts.addHandler(webApp)

            webApp.addFilter(FilterHolder(CorsFilter::class.java), "/*",
                    EnumSet.allOf(DispatcherType::class.java))

            webApp.setInitParameter("org.eclipse.jetty.servlet.Default.dirAllowed",
                    java.lang.Boolean.toString(conf.getBoolean(ConfVars.ZEPPELIN_SERVER_DEFAULT_DIR_ALLOWED)))

            return webApp
        }

        /**
         * Check if it is source build or binary package.
         *
         * @return
         */
        private fun isBinaryPackage(conf: ZeppelinConfiguration): Boolean {
            return !File(conf.getRelativeDir("zeppelin-web")!!).isDirectory
        }
    }
}

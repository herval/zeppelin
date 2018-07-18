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

import java.util.Date
import org.apache.commons.io.FileUtils
import org.apache.hadoop.conf.Configuration
import org.apache.hadoop.security.Groups
import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.authc.SimpleAccount
import org.apache.shiro.authz.AuthorizationInfo
import org.apache.shiro.authz.SimpleAuthorizationInfo
import org.apache.shiro.realm.AuthorizingRealm
import org.apache.shiro.subject.PrincipalCollection
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.io.UnsupportedEncodingException
import java.security.PublicKey
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey
import java.text.ParseException
import java.util.HashSet

import javax.servlet.ServletException

import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jwt.SignedJWT

/**
 * Created for org.apache.zeppelin.server.
 */
class KnoxJwtRealm : AuthorizingRealm() {

    var providerUrl: String? = null
    var redirectParam: String? = null
    var cookieName: String? = null
    var publicKeyPath: String? = null
    var login: String? = null
    var logout: String? = null
    var logoutAPI: Boolean? = null

    var principalMapping: String? = null
    var groupPrincipalMapping: String? = null

    private val mapper = SimplePrincipalMapper()

    /**
     * Configuration object needed by for Hadoop classes.
     */
    private var hadoopConfig: Configuration? = null

    /**
     * Hadoop Groups implementation.
     */
    private var hadoopGroups: Groups? = null

    override fun onInit() {
        super.onInit()
        if (principalMapping != null && !principalMapping!!.isEmpty() || groupPrincipalMapping != null && !groupPrincipalMapping!!.isEmpty()) {
            try {
                mapper.loadMappingTable(principalMapping!!, groupPrincipalMapping!!)
            } catch (e: PrincipalMappingException) {
                LOGGER.error("PrincipalMappingException in onInit", e)
            }

        }

        try {
            hadoopConfig = Configuration()
            hadoopGroups = Groups(hadoopConfig!!)
        } catch (e: Exception) {
            LOGGER.error("Exception in onInit", e)
        }

    }

    override fun supports(token: AuthenticationToken?): Boolean {
        return token != null && token is JWTAuthenticationToken
    }

    override fun doGetAuthenticationInfo(token: AuthenticationToken): AuthenticationInfo? {
        val upToken = token as JWTAuthenticationToken

        if (validateToken(upToken.token)) {
            try {
                val account = SimpleAccount(getName(upToken), upToken.token, name)
                account.addRole(mapGroupPrincipals(getName(upToken)))
                return account
            } catch (e: ParseException) {
                LOGGER.error("ParseException in doGetAuthenticationInfo", e)
            }

        }
        return null
    }

    @Throws(ParseException::class)
    fun getName(upToken: JWTAuthenticationToken): String {
        val signed = SignedJWT.parse(upToken.token!!)
        return signed.jwtClaimsSet.subject
    }

    fun validateToken(token: String?): Boolean {
        try {
            val signed = SignedJWT.parse(token!!)
            val sigValid = validateSignature(signed)
            if (!sigValid) {
                LOGGER.warn("Signature of JWT token could not be verified. Please check the public key")
                return false
            }
            val expValid = validateExpiration(signed)
            if (!expValid) {
                LOGGER.warn("Expiration time validation of JWT token failed.")
                return false
            }
            val currentUser = org.apache.shiro.SecurityUtils.getSubject().principal as String ?: return true
            val cookieUser = signed.jwtClaimsSet.subject
            return if (cookieUser != currentUser) {
                false
            } else true
        } catch (ex: ParseException) {
            LOGGER.info("ParseException in validateToken", ex)
            return false
        }

    }

    protected fun validateSignature(jwtToken: SignedJWT): Boolean {
        var valid = false
        if (JWSObject.State.SIGNED == jwtToken.state) {
            if (jwtToken.signature != null) {
                try {
                    val publicKey = parseRSAPublicKey(publicKeyPath)
                    val verifier = RSASSAVerifier(publicKey)
                    if (verifier != null && jwtToken.verify(verifier)) {
                        valid = true
                    }
                } catch (e: Exception) {
                    LOGGER.info("Exception in validateSignature", e)
                }

            }
        }
        return valid
    }

    /**
     * Validate that the expiration time of the JWT token has not been violated.
     * If it has then throw an AuthenticationException. Override this method in
     * subclasses in order to customize the expiration validation behavior.
     *
     * @param jwtToken
     * the token that contains the expiration date to validate
     * @return valid true if the token has not expired; false otherwise
     */
    protected fun validateExpiration(jwtToken: SignedJWT): Boolean {
        var valid = false
        try {
            val expires = jwtToken.jwtClaimsSet.expirationTime
            if (expires == null || Date().before(expires)) {
                if (LOGGER.isDebugEnabled) {
                    LOGGER.debug("SSO token expiration date has been " + "successfully validated")
                }
                valid = true
            } else {
                LOGGER.warn("SSO expiration date validation failed.")
            }
        } catch (pe: ParseException) {
            LOGGER.warn("SSO expiration date validation failed.", pe)
        }

        return valid
    }

    override fun doGetAuthorizationInfo(principals: PrincipalCollection): AuthorizationInfo {
        val roles = mapGroupPrincipals(principals.toString())
        return SimpleAuthorizationInfo(roles)
    }

    /**
     * Query the Hadoop implementation of [Groups] to retrieve groups for provided user.
     */
    fun mapGroupPrincipals(mappedPrincipalName: String): Set<String> {
        /* return the groups as seen by Hadoop */
        var groups: Set<String>? = null
        try {
            hadoopGroups!!.refresh()
            val groupList = hadoopGroups!!
                    .getGroups(mappedPrincipalName)

            if (LOGGER.isDebugEnabled) {
                LOGGER.debug(String.format("group found %s, %s",
                        mappedPrincipalName, groupList.toString()))
            }

            groups = HashSet(groupList)

        } catch (e: IOException) {
            if (e.toString().contains("No groups found for user")) {
                /* no groups found move on */
                LOGGER.info(String.format("No groups found for user %s", mappedPrincipalName))

            } else {
                /* Log the error and return empty group */
                LOGGER.info(String.format("errorGettingUserGroups for %s", mappedPrincipalName))
            }
            groups = HashSet()
        }

        return groups!!
    }

    companion object {
        private val LOGGER = LoggerFactory.getLogger(KnoxJwtRealm::class.java)

        @Throws(IOException::class, ServletException::class)
        fun parseRSAPublicKey(pem: String?): RSAPublicKey {
            val pemHeader = "-----BEGIN CERTIFICATE-----\n"
            val pemFooter = "\n-----END CERTIFICATE-----"
            val fullPem = pemHeader + pem + pemFooter
            var key: PublicKey? = null
            try {
                val fact = CertificateFactory.getInstance("X.509")
                val `is` = ByteArrayInputStream(
                        FileUtils.readFileToString(File(pem!!)).toByteArray(charset("UTF8")))
                val cer = fact.generateCertificate(`is`) as X509Certificate
                key = cer.publicKey
            } catch (ce: CertificateException) {
                var message: String? = null
                if (pem!!.startsWith(pemHeader)) {
                    message = "CertificateException - be sure not to include PEM header " + "and footer in the PEM configuration element."
                } else {
                    message = "CertificateException - PEM may be corrupt"
                }
                throw ServletException(message, ce)
            } catch (uee: UnsupportedEncodingException) {
                throw ServletException(uee)
            } catch (e: IOException) {
                throw IOException(e)
            }

            return key as RSAPublicKey
        }
    }
}

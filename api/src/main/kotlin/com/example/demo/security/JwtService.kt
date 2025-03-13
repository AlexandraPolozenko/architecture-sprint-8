package com.example.demo.security

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.SignedJWT
import okhttp3.OkHttpClient
import okhttp3.Request
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Service
import java.net.URL
import java.util.concurrent.ConcurrentHashMap

@Service
class JwtService(
        private val keycloakUrl: String = "http://keycloak:8080",
        private val realmName: String = "reports-realm",
        private val requiredRole: String = "prothetic_user"
) {
    private val logger = LoggerFactory.getLogger(JwtService::class.java)
    private val publicKeys = ConcurrentHashMap<String, JWK>()

    private val httpClient = OkHttpClient()

    fun fetchKeycloakPublicKeys() {
        try {
            val url = "$keycloakUrl/realms/$realmName/protocol/openid-connect/certs"
            logger.info("Fetching JWKS from: $url")

            val request = Request.Builder().url(url).build()
            val response = httpClient.newCall(request).execute()

            if (!response.isSuccessful) {
                throw RuntimeException("Failed to fetch public keys")
            }

            val jwks = JWKSet.parse(response.body?.string() ?: "")
            jwks.keys.forEach { key ->
                publicKeys[key.keyID] = key
            }

            logger.info("Loaded ${publicKeys.size} signing keys.")
        } catch (e: Exception) {
            logger.error("Error fetching Keycloak public keys", e)
        }
    }

    fun validateToken(token: String): UsernamePasswordAuthenticationToken? {
        try {
            val signedJWT = SignedJWT.parse(token)
            val keyId = signedJWT.header.keyID
            val publicKey = publicKeys[keyId]?.toRSAKey()?.toRSAPublicKey()

            if (publicKey == null) {
                logger.error("Public key not found for keyId: $keyId")
                return null
            }

            val verifier = RSASSAVerifier(publicKey)
            if (!signedJWT.verify(verifier)) {
                logger.error("Token signature is invalid")
                return null
            }

            val claims = signedJWT.jwtClaimsSet
            val audience = claims.audience ?: listOf()

            val roles = claims.getJSONObjectClaim("realm_access")?.get("roles") as? List<String> ?: listOf()

            if (!roles.contains(requiredRole)) {
                logger.warn("User lacks required role: $requiredRole")
                return null
            }

            return UsernamePasswordAuthenticationToken("user", null, listOf(SimpleGrantedAuthority("ROLE_USER")))
        } catch (e: Exception) {
            logger.error("Error validating token", e)
            return null
        }
    }
}
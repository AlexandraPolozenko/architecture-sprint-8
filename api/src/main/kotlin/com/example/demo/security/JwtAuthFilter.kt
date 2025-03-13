package com.example.demo.security

import com.example.demo.security.JwtService
import jakarta.servlet.FilterChain
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

class JwtAuthFilter(
        private val jwtService: JwtService
) : UsernamePasswordAuthenticationFilter() {

    override fun doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain) {
        val httpRequest = request as HttpServletRequest
        val token = httpRequest.getHeader("Authorization")?.removePrefix("Bearer ")

        if (!token.isNullOrEmpty()) {
            val authentication = jwtService.validateToken(token)
            if (authentication != null) {
                SecurityContextHolder.getContext().authentication = authentication
            }
        }

        chain.doFilter(request, response)
    }
}
package com.example.demo.security

import com.example.demo.security.JwtService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.logout.LogoutHandler

@Configuration
class SecurityConfig(
        private val jwtService: JwtService
) {
    @Bean
    fun securityFilterChain(http: HttpSecurity): HttpSecurity {
        return http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests { auth ->
                    auth
                            .requestMatchers(HttpMethod.GET, "/reports").authenticated()
                            .anyRequest().permitAll()
                }
                .addFilterBefore(JwtAuthFilter(jwtService), UsernamePasswordAuthenticationFilter::class.java)
    }
}
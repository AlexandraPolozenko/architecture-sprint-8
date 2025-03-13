package com.example.demo.controller

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.security.core.annotation.AuthenticationPrincipal


import java.security.Principal

@RestController
@RequestMapping("reports")
class ProductsController() {
    @GetMapping
    fun reports(@AuthenticationPrincipal principal: Principal?): Map<String, String> =
            if (principal != null) mapOf("reports" to "some generated content")
            else mapOf("error" to "Unauthorized")
}
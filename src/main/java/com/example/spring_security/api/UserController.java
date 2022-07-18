package com.example.spring_security.api;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/user")
public class UserController {

    @RequestMapping
    public String say(){
        return "hello user";
    }
}
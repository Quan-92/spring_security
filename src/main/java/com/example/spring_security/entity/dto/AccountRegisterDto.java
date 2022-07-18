package com.example.spring_security.entity.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor

public class AccountRegisterDto {
    private int id;
    private String username;
    private String password;
    private String confirmpassword;
    private int role;
}
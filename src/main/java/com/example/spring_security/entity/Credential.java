package com.example.spring_security.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Credential {
    private String accessToken;
    private String refreshToken;
    private long expiredAt;
    private String scope;
}
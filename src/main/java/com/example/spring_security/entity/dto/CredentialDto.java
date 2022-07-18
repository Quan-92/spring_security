package com.example.spring_security.entity.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class CredentialDto {
    private String accessToken;
    private String refreshToken;
    private long expiredAt;
    private String scope;

}
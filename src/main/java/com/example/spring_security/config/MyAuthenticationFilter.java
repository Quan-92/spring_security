package com.example.spring_security.config;

import com.example.spring_security.entity.dto.AccountLoginDto;
import com.example.spring_security.entity.dto.CredentialDto;
import com.example.spring_security.util.JwtUtil;
import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.naming.AuthenticationException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.stream.Collectors;


@Slf4j
@RequiredArgsConstructor
public class MyAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    final AuthenticationManager authenticationManager;

    @Override
    public Authentication attempAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            String jsonData = request.getReader().lines().collect(Collectors.joining());
            Gson gson = new Gson();
            AccountLoginDto accountLoginDto = gson.fromJson(jsonData, AccountLoginDto.class);
            UsernamePasswordAuthenticationToken userToken = new UsernamePasswordAuthenticationToken(accountLoginDto.getUsername(), accountLoginDto.getPassword());
            return authenticationManager.authenticate(userToken);

        } catch (IOException exception) {
            return null;
        }
    }
    @Override
    public void successfullAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException{
        User user  = (User) authResult.getPrincipal(); // get user that successfully login
        // generate tokens
        String accessToken = JwtUtil.generateToken(user.getUsername(), user.getAuthorities().iterator().next().getAuthority(), request.getRequestURL().toString(), JwtUtil.ONE_DAY * 7);
        // generate refesh token
        String refreshToken = JwtUtil.generateToken(user.getUsername(), user.getAuthorities().iterator().next().getAuthority(), request.getRequestURL().toString(), JwtUtil.ONE_DAY * 14);
        CredentialDto credential = new CredentialDto(accessToken, refreshToken, JwtUtil.ONE_DAY * 7,  "basic_ìnormation");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        Gson gson = new Gson();
        response.getWriter().println(gson.toJson(credential));
    }
    @Override
    protected  void  unsuccessfullAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException{
        HashMap<String, String> errors = new HashMap<>();
        errors.put("message", "Invalid information");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        Gson gson = new Gson();
        response.getWriter().println(gson.toJson(errors));
    }


}
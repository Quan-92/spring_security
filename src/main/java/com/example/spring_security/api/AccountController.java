package com.example.spring_security.api;

import com.example.spring_security.entity.dto.AccountLoginDto;
import com.example.spring_security.entity.dto.AccountRegisterDto;
import com.example.spring_security.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/account")
@RequiredArgsConstructor
public class AccountController {
    final AccountService accountService;

    @RequestMapping(path = "register", method = RequestMethod.POST)
    public ResponseEntity<?> register(@RequestBody AccountRegisterDto accountRegisterDto) {
        return ResponseEntity.ok().body(accountService.register(accountService.register(accountRegisterDto)));

    }

    @RequestMapping(path = "login", method = RequestMethod.POST)
    public ResponseEntity<?> login(@RequestBody AccountLoginDto accountLoginDto) {
        return ResponseEntity.ok().body(accountService.login(accountLoginDto));
    }

    @RequestMapping(method = RequestMethod.GET)
    public String getInformation() {
        return "";
    }
}
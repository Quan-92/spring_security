package com.example.spring_security.service;

import com.example.spring_security.entity.Account;
import com.example.spring_security.entity.Credential;
import com.example.spring_security.entity.dto.AccountLoginDto;
import com.example.spring_security.entity.dto.AccountRegisterDto;
import com.example.spring_security.repository.AccountRepository;
import com.example.spring_security.util.JwtUtil;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AccountService implements UserDetailsService {
    final AccountRepository accountRepository;
    final PasswordEncoder passwordEncoder;

    public AccountRegisterDto register(AccountRegisterDto accountRegisterDto) {
        Optional<Account> optionalAccount = accountRepository.findAccountByUsername(accountRegisterDto.getUsername());
        if (optionalAccount.isPresent()) {
            return null;
        }
        Account account = Account.builder()
                .username(accountRegisterDto.getUsername())
                .passwordHash(passwordEncoder.encode(accountRegisterDto.getPassword()))
                .role(accountRegisterDto.getRole())
                .build();
        accountRepository.save(account);
        accountRegisterDto.setId((int) account.getId());
        return accountRegisterDto;
    }

    public Credential login(AccountLoginDto accountLoginDto) {
        // 1. tim user theo username
        Optional<Account> optionalAccount = accountRepository.findAccountByUsername(accountLoginDto.getUsername());
        if (!optionalAccount.isPresent()) {
            throw new UsernameNotFoundException("user is not found!");
        }
        Account account = optionalAccount.get();
        // so sanh password match
        boolean isMatch = passwordEncoder.matches(accountLoginDto.getPassword(), account.getPasswordHash());
        if (isMatch) {
            int expiredAfterDay = 7;
            String accessToken = JwtUtil.generateTokenByAccount(account, expiredAfterDay * 24 * 60 * 60 * 1000);
            String refreshToken = JwtUtil.generateTokenByAccount(account, 14 * 24 * 60 * 60 * 1000);
            Credential credential = new Credential();
            Credential.setAccessToken(accessToken);
            Credential.setRefreshToken(refreshToken);
            Credential.setExpiredAt(expiredAfterDay);
            Credential.setScope("basic_information");
            return credential;
        } else {
            throw new UsernameNotFoundException("password is not match");
        }
    }

    public void getInformation() {

    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Account> optionalAccount = accountRepository.findAccountByUsername(username);
        if (!optionalAccount.isPresent()) {
            throw new UsernameNotFoundException("user name is not found;");
        }
        Account account = optionalAccount.get();
        List<GrantedAuthority> authorities = new ArrayList<>();
        SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(account.getRole() == 1 ? "Admin" : "user");
        authorities.add(simpleGrantedAuthority);
        return new User(account.getUsername(), account.getPasswordHash(), authorities);
    }
}
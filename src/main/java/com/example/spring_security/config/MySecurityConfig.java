package com.example.spring_security.config;


import com.example.spring_security.service.AccountService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
    final AccountService accountService;
    final PasswordEncoder passwordEncoder;

    public MySecurityConfig(AccountService accountService, PasswordEncoder passwordEncoder) {
        this.accountService = accountService;
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception{
        return  super.authenticationManagerBean();
    }
    @Override
    protected void configure (AuthenticationManagerBuilder auth) throws Exception{
        auth.userDetailsService(accountService).passwordEncoder(passwordEncoder);
    }

    protected void configure(HttpSecurity httpSecurity) throws Exception{
        MyAuthenticationFilter authenticationFilter = new MyAuthenticationFilter( authenticationManagerBean());
        authenticationFilter.setFilterProcessesUrl("/api/v1/accounts/login");
        httpSecurity.cors().and().csrf().disable();
        httpSecurity.authorizeHttpRequests().antMatchers("/api/v1/hello", "/api/v1/account/*").permitAll();
        httpSecurity.authorizeHttpRequests().antMatchers("/api/v1/user").hasAnyAuthority("USER", "ADMIN");
        httpSecurity.authorizeHttpRequests().antMatchers("/api/v1/admin").hasAnyAuthority("ADMIN");
        httpSecurity.addFilterBefore(new MyAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}
package com.example.sts.config;

import com.example.sts.eo.ERole;
import com.example.sts.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService) // UserDetailsService 등록
                .passwordEncoder(bCryptPasswordEncoder); // password 인코딩 방식 설정
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers("/css/**", "/js/**", "/image/**", "/lib/**"); // 시큐리티 인증시 제외 될 항목
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/", "/login", "/registration", "/h2/**").permitAll()
                .antMatchers("/home/admin").hasAuthority(ERole.ADMIN.getValue())
                .antMatchers("/home/user").hasAuthority(ERole.MANAGER.getValue())
                .antMatchers("/home/guest").hasAuthority(ERole.GUEST.getValue())
                .anyRequest().authenticated() // 이 외 모든 페이지는 인증된(로그인한) 사용자만 접근 가능
                .and()
                .csrf()
                .disable()
                .headers()
                .frameOptions().disable()
                .and()
                .formLogin()
                .loginPage("/login") // 로그인 페이지 설정, 미설정시 security가 기본으로 제공하는 Default 페이지 제공
                .defaultSuccessUrl("/home") // 로그인 성공 후 이동할 페이지 설정
                .failureUrl("/login?error=true") // 로그인 실패 시 이동할 페이지 설정
                .successHandler(successHandler()) // 로그인 성공 후 페이지 이동하기 전 처리할 핸들러 지정
                .failureHandler(failureHandler()) // 로그인 실패 후 페이지 이동하기 전 처리할 핸들러 지정
                .usernameParameter("username")
                .passwordParameter("password")
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동할 페이지 설정
                .and()
                .exceptionHandling() // 접근이 불가능한 페이지 요청 시 후처리 작업등을 설정
                .accessDeniedPage("/access-denied"); // 접근 불가 페이지 요청 시 이동할 경로
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        return bCryptPasswordEncoder;
    }

    @Bean
    public AuthenticationSuccessHandler successHandler() {
        return new CustomAuthSuccesshandler();
    }

    @Bean
    public AuthenticationFailureHandler failureHandler() {
        return new CustomAuthFailureHandler();
    }
}

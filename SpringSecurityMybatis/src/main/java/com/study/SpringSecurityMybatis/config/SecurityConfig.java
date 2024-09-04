package com.study.SpringSecurityMybatis.config;

import com.study.SpringSecurityMybatis.security.filter.JwtAccessTokenFilter;
import com.study.SpringSecurityMybatis.security.handler.AuthenticationHandler;
import com.study.SpringSecurityMybatis.security.handler.OAuth2SuccessHandler;
import com.study.SpringSecurityMybatis.service.OAuth2Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtAccessTokenFilter jwtAccessTokenFilter;
    @Autowired
    private AuthenticationHandler authenticationHandler;
    @Autowired
    private OAuth2SuccessHandler oAuth2SuccessHandler;
    @Autowired
    private OAuth2Service oAuth2Service;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin().disable();
        http.httpBasic().disable();
        http.csrf().disable();
        http.headers().frameOptions().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.cors();

        http.oauth2Login() // OAuth2 로그인 기능에 대한 여러 설정의 진입점
                .successHandler(oAuth2SuccessHandler) // OAuth2 로그인 성공 핸들러
                .userInfoEndpoint() //  OAuth2 로그인 성공 이후 사용자 정보를 가져올 때의 설정들을 담당
                .userService(oAuth2Service); // 소셜 로그인 성공 시 후속 조치를 진행할 UserService 인터페이스의 구현체를 등록

        http.exceptionHandling() // 예외 처리를 진행
                .authenticationEntryPoint(authenticationHandler); // 인증이 필요한 페이지에 접근했을 때, 인증이 되지 않은 상태라면 AuthenticationEntryPoint를 호출

        http.authorizeRequests() // HttpServletRequest에 따라 접근(access)을 제한
                .antMatchers("/auth/**", "/h2-console/**") // 권한 관리 대상을 지정하는 옵션
                .permitAll() // 권한 관리 대상을 지정하는 옵션
                .anyRequest() // 설정된 값들 이외 나머지 URL
                .authenticated(); // 설정된 값들 이외 나머지 URL

        http.addFilterBefore(jwtAccessTokenFilter, UsernamePasswordAuthenticationFilter.class); // JwtAccessTokenFilter를 UsernamePasswordAuthenticationFilter 전에 넣기
    }

}

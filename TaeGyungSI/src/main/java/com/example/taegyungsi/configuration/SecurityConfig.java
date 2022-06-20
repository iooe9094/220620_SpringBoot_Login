package com.example.taegyungsi.configuration;

import com.example.taegyungsi.security.JwtAuthenticationFilter;
import com.example.taegyungsi.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * packageName : com.example.taegyungsi.configuration
 * fileName : SecurityConfig
 * author : macbook
 * date : 6/20/22
 * description :
 * ===========================================================
 * DATE            AUTHOR             NOTE
 * -----------------------------------------------------------
 * 6/20/22         macbook          최초 생성
 */

// @EnableWebSecurity: 보안 설정(JWT, SpringSecurity 등) 사용 시 아래 어노테이션
@EnableWebSecurity
// @REquiredArgsConstructor: (lombok) final, @NotNull 붙은 변수를 가진 생성자를 생성
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 웹 토큰 생성, 인증 등 메소드를 위한 변수 정의
    private final JwtTokenProvider jwtTokenProvider;

    // 패스워드 암호화 메소드
    @Bean
    public PasswordEncoder getPasswordEncoder() {
        // Springboot에서 제공하는 암호화 메소드
        return new BCryptPasswordEncoder();
    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    // 보안 설정: 규칙 적용 (이 사이트에 적용할 규칙을 정의)
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // 1) 기본 설정(세팅)
                // rest API 아니라면 기본 제공되는 로그인 화면이 있음
                .httpBasic().disable() // rest API 기반이므로 비활성화
                .csrf().disable() // rest API csrf 보안이 필요 없으므로 비활성화
                // 기본 값: 세션 인증
                // JWT 인증을 사용하므로 세션 인증 사용안함(STATELESS)
                // 세션 인증 사용(SessionCreationPolicy.ALWAYS)
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                // 2) 추가 설정 (권한 설정: ROLE_USER, ROLE_ADMIN)
                .and()
                .authorizeRequests() // 화면을 접근할 수 있는 권한 설정 체크
                // 아래 주소로 접근하면 모두 허용
                .antMatchers("/api/**").permitAll()
                // 나머지 화면에 ROLE_USER 권한이 있는 사람만 접근
                .anyRequest().hasRole("USER")
                // 3) 토큰을 필터로 끼워넣기
                .and()
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider),
                        UsernamePasswordAuthenticationFilter.class);

    }

}

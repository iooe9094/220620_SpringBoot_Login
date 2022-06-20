package com.example.taegyungsi.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * packageName : com.example.taegyungsi.security
 * fileName : JwtAuthenticationFilter
 * author : macbook
 * date : 6/20/22
 * description : JWT(Jason Web Token) 유효한 토큰인지 인증하기 위한 filter
 *               (SpringBoot Security는 필터들로 인증 진행)
 *               유효하면 SecurityContextHolder 저장(인증 객체로 저장) : setter
 * ===========================================================
 * DATE            AUTHOR             NOTE
 * -----------------------------------------------------------
 * 6/20/22         macbook          최초 생성
 */
// GenericFilterBean -> 스프링에서 제공
public class JwtAuthenticationFilter extends GenericFilterBean {

    // 토큰 관련 다양한 메소드를 사용하기 위한 객체 정의
    private JwtTokenProvider jwtTokenProvider;

    // 기본 생성자 정의
    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public void doFilter(ServletRequest request,
                         ServletResponse response,
                         FilterChain chain)
            throws IOException, ServletException {
            // http 헤더에서 토큰 받아오기 (Vue에서 토큰 전송)
            String token = jwtTokenProvider
                    .resolveToken((HttpServletRequest) request);
            // Vue에서 보낸 웹 토큰이 유효한 지 인증 시작
            if(token != null && jwtTokenProvider.validateToken(token)) {
                // if문 안에 들어오면 웹 토큰이 유효함
                // 1) 웹 토큰이 유효하면 JWT 토큰으로 DB에 유저 정보를 조회
                // 2) 해당 유저 인증됨
               Authentication auth =
                       jwtTokenProvider.getAuthentication(token);
               // 관리를 위해 아래 클래스 객체에 저장
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
            // 필터에 등록하기
        chain.doFilter(request, response);
    }
}

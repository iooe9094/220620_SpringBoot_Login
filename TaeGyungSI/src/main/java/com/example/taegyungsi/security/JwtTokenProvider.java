package com.example.taegyungsi.security;

import com.example.taegyungsi.service.CustomUserDetailService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/**
 * packageName : com.example.taegyungsi.security
 * fileName : JwtTokenProvider
 * author : Seok
 * date : 2022-06-20
 * description : JWT 웹토큰을 생성, 인증, 권한부여, 유효성검사, PK 추출 등을
 *              다양한 기능을 제공하는(메소드) 클래스
 * ===========================================================
 * DATE            AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2022-06-20         Seok         최초 생성
 */
// 보안관련 모듈은 아래 어노테이션 적용 ( JWT )
//@EnableWebSecurity

// @RequiredArgsConstructor : Lombok 어노테이션 : final 이나 @NotNull 이 붙은 멤버변수를 가지는 생성자를 만듬
@RequiredArgsConstructor
// @Component : Springboot 에 객체로 생성 ( @service, @mapper )
@Component
public class JwtTokenProvider {

    Logger logger = LoggerFactory.getLogger(this.getClass());

    // 위변조 방지 : JWT(웹토큰) -> 서버 쪽으로 날렸음 (JWT + secretKey) 인증
    // @Value : spring.jwt.secret 에 접근할 수 있는 어노테이션
    @Value("spring.jwt.secret")
    private String secretKey; // JWT 인증키를 담을 변수 9application.properties 에서 가져옴)

    // 만료시간 변수(밀리세컨드(1000분의1초)) : 1시간만 토큰이 유효
    private long tokenValidMillisecond = 60 * 60 * 1000L;

    // DB 에 접속해서 User 객체정보를 가져오는 서비스
    private final CustomUserDetailService customUserDetailService;

    // @PostConstruct : @Autowired(스프링에서 객체 받아오기) 이후에 초기화 진행하는 생성자
    // 역할 : secretKey (일반 문자열 pepega524832857240 ) 를 Base64 인코딩으로 변환
    // * Base64 : binary 데이터를 text 로 변환 ( 목적 : 보안, 표준화 등등 )
    // 초기화 메소드 init()
    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    // JWT 토큰 생성 메소드
    public String createToken(String userId, List<String> roles) {
        // JWT 내용(playload) 부분에 sub(제목)에 id를 저장
        Claims claims = Jwts.claims().setSubject(userId);
        // 역할 (ROLE_USER, ROLE_ADMIN)
        claims.put("roles", roles);
        // 현재 날짜
        Date now = new Date();

        // 실제 웹토큰 생성하는 부분
        // 생성자 or setter or builder
        return Jwts.builder()
                .setClaims(claims) // 클레임 데이터터
                .setIssuedAt(now) // 토큰 발행 날짜
                // 토큰 만료 시간 ( 현재 시간 + 1시간 )
                .setExpiration(new Date(now.getTime() + tokenValidMillisecond))
                // secretKey 에 암호화 알고리즘 적용
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact(); // 최종 생성자 빌드
    }

    // JWT 토큰에서 id 로 추출하는 메소드
    public String getUserId(String token) {
        return Jwts.parser()
                // setSigningKey 안에 secretKey 를 매개변수로 넣으면
                // (secretKey + token) 토큰을 해석
                .setSigningKey(secretKey)
                .parseClaimsJws(token) // 위에 해석한 토큰을 문자열로 변환
                .getBody()
                .getSubject(); // 웹토큰에서 회원정보 id 가 추출
    }

    // JWT 토큰으로 추출한 id 로 인증 정보를 조회하는 메소드
    // Authentication == user == UserDetails : 인증된 회원정보를 가지는 객체
    public Authentication getAuthentication(String token) {
        // 토큰(인증키)으로 회원정보 얻기
        // UserDetails userDetails 에는 User 객체 정보도 있지만 권한 정보도 있음 (CustomUserDetailService.jave)
        UserDetails userDetails = customUserDetailService.loadUserByUsername(this.getUserId(token));

        // UsernamePasswordAuthenticationToken 호출하면 인증된 객체가 나옴
        // 인증된 객체(유저정보)가 Authentication 에 저장됨
        // 메소드 이름이 긴 이유 : Username + Password + Authentication + Token
        return new UsernamePasswordAuthenticationToken(userDetails, userDetails.getAuthorities());
    }

    // 유틸리티성 메소드 : html 등 헤더 정보 확인 메소드
    // 확인 : 토큰 정보 확인 ("Authorization: 'Bearer'")
    // ex) X-AUTH-TOKEN: 웹 토큰
    //     Authorization: 'Bearer' + 웹토큰
    public String resolveToken(HttpServletRequest req) {
        // return req.getHeader("X-AUTH-TOKEN");
        return req.getHeader("Authorization: 'Bearer'");
    }

    // 유틸리티성 메소드
    // JWT 웹 토큰의 유효성 + 만료일자 확인하는 메소드
    // 만료 시간 안에 있으면 반환값이 true
    // 만료 시간 지나면 반환값이 false
    public boolean validateToken(String jwtToken) {
        try {
            Jws<Claims> claims = Jwts.parser()
                    // setSigningKey 안에 secretKey 를 매개변수로 넣으면
                    // (secretKey + token) 토큰을 해석
                    .setSigningKey(secretKey)
                    .parseClaimsJws(jwtToken); // 위에 해석한 토큰을 문자열로 변환
            // Date date = claims.getBody().getExpiration();
            return !claims.getBody().getExpiration().before(new Date());
        } catch (Exception e) {
            logger.info("validateToken Error {}", e.getMessage());

            return false;
        }
    }
}
package com.security.basicsecurity;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		// 우선 시큐리티 기본 정책 그대로 적용 (2) 사용자 정의 보안 기능 구현)
		http
			.authorizeRequests()	// 인가요청
			.anyRequest()			// 어떤 요청에도
			.authenticated();		// 인증을 거치도록 설정 (spring security 기본설정)

		// 인증정책 ( 3) Form Login 인증 )
		http
			.formLogin()	 					// 기본적인 formLogin 방식 인증 시작을 알림
			.loginPage("/loginPage")			// 로그인 페이지 설정 (spring security 기본 로그인 창이 싫다면)
			.defaultSuccessUrl("/")				// 인증 성공 시 리다이렉트 될 URL
			.failureUrl("/login")				// 인증 실패 시 리다이렉트 될 URL
			.usernameParameter("userId")		// ID 파라미터명 지정
			.passwordParameter("passwd")		// PWD 파라미터명 지정
			.loginProcessingUrl("/login_proc")	// 로그인 Form Action Url (login_proc는 이미 시큐리티에서 존재하는 페이지)
			.successHandler(new AuthenticationSuccessHandler() {	// 로그인 성공 후 핸들러 (여기선 직접 작성해줌)
				@Override
				public void onAuthenticationSuccess(HttpServletRequest request,
					HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
					System.out.println("authentication = " + authentication.getName());
					response.sendRedirect("/");
				}
			})
			.failureHandler(new AuthenticationFailureHandler() {	// 로그인 실패 후 호출될 핸들러
				@Override
				public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
					AuthenticationException exception) throws IOException, ServletException {
					System.out.println("exception.getMessage() = " + exception.getMessage());
					response.sendRedirect("/login");
				}
			})
			.permitAll();	// "/loginPage"로 접근은 누구나 가능해야 함으로 설정

	}

}

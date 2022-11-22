package com.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http
			.authorizeRequests()	// 인가요청
			.anyRequest()			// 어떤 요청에도
			.authenticated();		// 인증을 거치도록 설정 (spring security 기본설정)

		// 인증정책
		http
			.formLogin();	 		// 기본적인 formLogin 방식 인증
	}

}

package com.shiraj.springsecuritypractice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@SpringBootApplication
@EnableWebSecurity
public class SpringsecuritypracticeApplication extends WebSecurityConfigurerAdapter {

	public static void main(String[] args) {
		SpringApplication.run(SpringsecuritypracticeApplication.class, args);
	}


	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers("/","index","/css/*","/js/*")
				.permitAll()
				.anyRequest()
				.authenticated()
				.and()
				.httpBasic();
	}


	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		UserDetails userDetails = User.builder()
				.username("shiraj")
				.password("password")
				.roles("STUDENT")
				.build();

		return new InMemoryUserDetailsManager(
				userDetails
		);
	}

}

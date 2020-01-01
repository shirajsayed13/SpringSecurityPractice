package com.shiraj.springsecuritypractice;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.shiraj.springsecuritypractice.ApplicationUserRole.ADMIN;
import static com.shiraj.springsecuritypractice.ApplicationUserRole.STUDENT;

@SpringBootApplication
@EnableWebSecurity
public class SpringsecuritypracticeApplication extends WebSecurityConfigurerAdapter {

	public static void main(String[] args) {
		SpringApplication.run(SpringsecuritypracticeApplication.class, args);
	}

	private final PasswordEncoder passwordEncoder;

	@Autowired
	public SpringsecuritypracticeApplication(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers("/","index","/css/*","/js/*").permitAll()
				.antMatchers("/api/**").hasRole(STUDENT.name())
				.anyRequest()
				.authenticated()
				.and()
				.httpBasic();
	}


	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		UserDetails usersShiraj = User.builder()
				.username("shiraj")
				.password(passwordEncoder.encode("password"))
				.roles(STUDENT.name())
				.build();

		UserDetails usersJames = User.builder()
				.username("james")
				.password(passwordEncoder.encode("pass123"))
				.roles(ADMIN.name())
				.build();

		return new InMemoryUserDetailsManager(
				usersShiraj, usersJames
		);
	}

}

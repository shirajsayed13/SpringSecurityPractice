package com.shiraj.springsecuritypractice;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.util.concurrent.TimeUnit;

import static com.shiraj.springsecuritypractice.ApplicationUserPermission.COURSE_WRITE;
import static com.shiraj.springsecuritypractice.ApplicationUserRole.*;

@SpringBootApplication
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
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
        http
                //.csrf().disable()
                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                /*.antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())*/
                .anyRequest()
                .authenticated()
                .and()
				.httpBasic();

				// cookie code
                //.and().rememberMe().tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21)); // custom time of 21 days
                //.and().rememberMe(); // Default time 2-weeks

				// logout code
				/*.and()
                .logout()
                .logoutUrl("/logout")
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "remember-me")
                .logoutSuccessUrl("/login");*/
    }


    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails userShiraj = User.builder()
                .username("shiraj")
                .password(passwordEncoder.encode("password"))
//				.roles(STUDENT.name()) //ROLE_STUDENT
                .authorities(STUDENT.getSimpleGrantedAuthorities())
                .build();

        UserDetails userJames = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
//				.roles(ADMIN.name())  //ROLE_ADMIN
                .authorities(ADMIN.getSimpleGrantedAuthorities())
                .build();

        UserDetails userTom = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password123"))
//				.roles(ADMINTRAINEE.name()) //ROLE_ADMINTRAINEE
                .authorities(ADMINTRAINEE.getSimpleGrantedAuthorities())
                .build();


        return new InMemoryUserDetailsManager(
                userShiraj,
                userJames,
                userTom
        );
    }

}

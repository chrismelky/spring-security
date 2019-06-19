package org.softalanta.securityPlay.config;

import org.softalanta.securityPlay.security.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@EnableGlobalMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true
)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    CustomUserDetailsService customUserDetailsService;

    @Autowired
    CustomOauth2UserService customOauth2UserService;

    @Autowired
    CustomOpenIdConnectUserService customOpenIdConnectUserService;

    @Autowired
    OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    @Autowired
    OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;


    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    HttpCookieOAuth2AuthorizationRequestRepository cookieOAuth2AuthorizationRequestRepository(){
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
         http.cors()
                 .and()
              .sessionManagement()
                 .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                 .and()
              .csrf()
                 .disable()
              .formLogin()
                 .disable()
              .httpBasic()
                 .disable()
              .exceptionHandling()
                 .authenticationEntryPoint(new RestAuthEntryPoint())
                 .and()
              .authorizeRequests()
                 .antMatchers("/auth/**","/oauth2/**","/login")
                 .permitAll()
              .anyRequest()
                 .authenticated()
                 .and()
              .oauth2Login()
                 .authorizationEndpoint()
                    .baseUri("/oauth2/authorize")
                    .authorizationRequestRepository(cookieOAuth2AuthorizationRequestRepository())
                 .and()
                 .redirectionEndpoint()
                    .baseUri("/oauth2/callback/*")
                 .and()
                 .userInfoEndpoint()
                    .userService(customOauth2UserService)
                    .oidcUserService(customOpenIdConnectUserService)
                 .and()
                 .successHandler(oAuth2AuthenticationSuccessHandler)
                 .failureHandler(oAuth2AuthenticationFailureHandler);

         http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}

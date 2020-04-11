package dev.sanda.authentifi.config;

import dev.sanda.jwtauthtemplate.security.jwt.JwtSecurityConfigurer;
import dev.sanda.jwtauthtemplate.security.jwt.JwtTokenProvider;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.cors.CorsConfiguration;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationServerConfiguration configuration;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Override
    public AuthenticationManager authenticationManagerBean(){
        return configuration.authenticationManager();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //@formatter:off
        http
            .httpBasic()
            .disable()
            .csrf()
            .disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .authorizeRequests()
                .antMatchers("/auth/signin", "/auth/signup", "/auth/invitation-signup").permitAll()
                .antMatchers(configuration.publicUrls()).permitAll()
                .anyRequest().authenticated()
            .and()
            .apply(new JwtSecurityConfigurer(jwtTokenProvider))
            .and()
            .cors()
            .configurationSource(httpServletRequest -> {
                val corsConfiguration = new CorsConfiguration();
                corsConfiguration.setAllowedOrigins(configuration.allowedOrigins());
                return corsConfiguration;
            });
        //@formatter:on
    }


}


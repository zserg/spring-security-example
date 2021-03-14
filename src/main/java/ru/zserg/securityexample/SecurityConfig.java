package ru.zserg.securityexample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private static final RequestMatcher PROTECTED_URLS = new OrRequestMatcher(
            new AntPathRequestMatcher("/api/**")
    );

    @Autowired
    LocalAdminAuthenticationProvider authenticationProvider;

    @Autowired
    SecurityContextRepository securityContextRepository;

    @Configuration
    @Order(1)
    public static class PermitAllWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http.cors()
                    .and()
                    .antMatcher("/api/v1/auth")
                    .authorizeRequests()
                    .anyRequest().permitAll()
                    .and()
                    .csrf().disable()
                    .formLogin().disable()
                    .httpBasic().disable();
        }
    }

    @Configuration
    @Order(2)
    public static class JwtWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            final JWTAuthorizationFilter filter = new JWTAuthorizationFilter(PROTECTED_URLS);
            filter.setAuthenticationManager(authenticationManager());
            http.cors()
                    .and()
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .disable()
                    .addFilterAfter(filter, UsernamePasswordAuthenticationFilter.class)
                    .authorizeRequests()
                    .anyRequest()
                    .authenticated()
                    .and()
                    .csrf().disable()
                    .formLogin().disable()
                    .httpBasic().disable();
        }
    }

//    @Bean
//    JWTAuthorizationFilter authenticationFilter() throws Exception {
//        final JWTAuthorizationFilter filter = new JWTAuthorizationFilter(PROTECTED_URLS);
//        filter.setAuthenticationManager(authenticationManager());
//        return filter;
//    }
}

package ru.zserg.securityexample;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import java.io.Serializable;
import java.util.List;

@Slf4j
@Component
public class LocalAdminAuthenticationProvider implements AuthenticationProvider, Serializable {

    @Override
    public Authentication authenticate(Authentication req) throws AuthenticationException {

        log.info("authenticate");
        String authToken = req.getCredentials().toString();
        log.info("token: {}", authToken);

        if (authToken.equals("123")) {
            UsernamePasswordAuthenticationToken springUserDetails =
                    new UsernamePasswordAuthenticationToken(req.getPrincipal(), authToken, List.of(new SimpleGrantedAuthority("API_ACCESS")));
            return springUserDetails;
        } else {
            log.error("user {} send invalid token {}", req.getPrincipal(), authToken);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, null);
        }
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

}

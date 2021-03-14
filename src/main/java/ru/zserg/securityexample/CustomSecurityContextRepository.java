package ru.zserg.securityexample;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@Component
public class CustomSecurityContextRepository implements SecurityContextRepository {

    private final LocalAdminAuthenticationProvider localAdminAuthenticationProvider;

    @Autowired
    public CustomSecurityContextRepository(LocalAdminAuthenticationProvider localAdminAuthenticationProvider) {
        this.localAdminAuthenticationProvider = localAdminAuthenticationProvider;
    }

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder httpRequestResponseHolder) {
        try {
            log.info("load`Context");
            HttpServletRequest request = httpRequestResponseHolder.getRequest();
            String authHeader = request.getHeaders(HttpHeaders.AUTHORIZATION).nextElement();
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String authToken = authHeader.substring(7);
                Authentication auth = localAdminAuthenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(authToken, authToken));
                httpRequestResponseHolder.getResponse().setHeader("token", "abcdef");
                return new SecurityContextImpl(auth);
            } else {
                return SecurityContextHolder.createEmptyContext();
            }
        }catch (Exception e){
            return SecurityContextHolder.createEmptyContext();
        }
    }

    @Override
    public void saveContext(SecurityContext securityContext, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
//        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean containsContext(HttpServletRequest httpServletRequest) {
        return false;
    }
}

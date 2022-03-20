package com.alewol.spring.securityjwtdemo.filter;

import static com.alewol.spring.securityjwtdemo.constants.Paths.ROOT;
import static com.alewol.spring.securityjwtdemo.constants.Paths.TOKEN;
import static com.alewol.spring.securityjwtdemo.util.AuthorizationHeaderHelper.checkAuthorizationHeaderException;
import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)throws ServletException, IOException {
        if(request.getServletPath().equals("/" + ROOT + "login") || request.getServletPath().equals("/" + ROOT + TOKEN + "refresh")) {
            filterChain.doFilter(request, response);
        }
        else
        {
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            if(authorizationHeader != null && authorizationHeader.startsWith("Bearer "))
            {
                try
                {
                    String token = authorizationHeader.substring("Bearer ".length());
                    //TODO Refactor doublecated code in util class
                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                    JWTVerifier verifier = JWT.require(algorithm).build();
                    DecodedJWT decodedJWT= verifier.verify(token);
                    String username = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);

                    //Convert Roles to Spring GrantedAuthoritys
                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    stream(roles).forEach(role -> {
                        authorities.add(new SimpleGrantedAuthority(role));
                    });
                    
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    filterChain.doFilter(request, response);
                }
                catch (Exception exception) {
                    log.error("Error loggin in: {}", exception.getMessage());

                    checkAuthorizationHeaderException(response, exception);
                }
            }
            else
            {
                log.info("Missing auth header");
                filterChain.doFilter(request, response);
            }
        };

        
    }

}

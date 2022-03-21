package com.alewol.spring.securityjwtdemo.filter;

import static com.alewol.spring.securityjwtdemo.util.JwtHelper.getAccessTokenTimeout;
import static com.alewol.spring.securityjwtdemo.util.JwtHelper.getRefreshTokenTimeout;
import static com.alewol.spring.securityjwtdemo.util.JwtHelper.jwtEncriptionAlgorithm;
import static com.alewol.spring.securityjwtdemo.util.JwtHelper.writeJwtJson;

import java.io.IOException;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.extern.slf4j.Slf4j;;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        log.info("Username is: {}", username);
        log.info("Password is: {}", password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException{
        User user = (User)authentication.getPrincipal();
        String access_token = JWT.create()
        .withSubject(user.getUsername())
        .withExpiresAt(getAccessTokenTimeout())
        .withIssuer(request.getRequestURL().toString())
        .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
        .sign(jwtEncriptionAlgorithm);

        String refresh_token = JWT.create()
        .withSubject(user.getUsername())
        .withExpiresAt(getRefreshTokenTimeout())
        .withIssuer(request.getRequestURL().toString())
        .sign(jwtEncriptionAlgorithm);

        writeJwtJson(response, access_token, refresh_token);
    }
}

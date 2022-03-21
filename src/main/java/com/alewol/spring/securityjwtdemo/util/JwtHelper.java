package com.alewol.spring.securityjwtdemo.util;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JwtHelper {

    public static final String HeaderPrefix = "Bearer ";
    //TODO use encrypted String instead of "secret"
    public static final Algorithm jwtEncriptionAlgorithm = Algorithm.HMAC256("secret".getBytes());


    public static void checkAuthorizationHeaderException(HttpServletResponse response, Exception exception) throws IOException {
        response.setHeader("error", exception.getMessage());
        //response.sendError(FORBIDDEN.value());
        Map<String, String> error = new HashMap<>();
        error.put("error_message", exception.getMessage());
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), error);
    }

    public static DecodedJWT getDecodedJWT (String jwtString){
        JWTVerifier verifier = JWT.require(jwtEncriptionAlgorithm).build();
        DecodedJWT decodedJWT= verifier.verify(jwtString);
        
        return decodedJWT;
    }

    public static Date getRefreshTokenTimeout(){
        // 30 Minutes Timeout
        Date refreshTokenTimeout = new Date(System.currentTimeMillis() + 30 * 60 * 1000 );
        return refreshTokenTimeout;
    }

    public static Date getAccessTokenTimeout(){
        // 10 Minutes Timeout
        Date refreshTokenTimeout = new Date(System.currentTimeMillis() + 10 * 60 * 1000 );
        return refreshTokenTimeout;
    }

    public static void writeJwtJson(HttpServletResponse response, String access_token, String refresh_token) throws IOException{
        //response.setHeader("access_token", access_token);
        //response.setHeader("refresh_token", refresh_token);
        
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }
    
}

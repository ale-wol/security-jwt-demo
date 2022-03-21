package com.alewol.spring.securityjwtdemo.controller;

import static com.alewol.spring.securityjwtdemo.constants.Paths.ROLE;
import static com.alewol.spring.securityjwtdemo.constants.Paths.ROOT;
import static com.alewol.spring.securityjwtdemo.constants.Paths.TOKEN;
import static com.alewol.spring.securityjwtdemo.constants.Paths.USER;
import static com.alewol.spring.securityjwtdemo.util.JwtHelper.HeaderPrefix;
import static com.alewol.spring.securityjwtdemo.util.JwtHelper.checkAuthorizationHeaderException;
import static com.alewol.spring.securityjwtdemo.util.JwtHelper.getAccessTokenTimeout;
import static com.alewol.spring.securityjwtdemo.util.JwtHelper.getDecodedJWT;
import static com.alewol.spring.securityjwtdemo.util.JwtHelper.jwtEncriptionAlgorithm;
import static com.alewol.spring.securityjwtdemo.util.JwtHelper.writeJwtJson;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.alewol.spring.securityjwtdemo.model.AppUser;
import com.alewol.spring.securityjwtdemo.model.Role;
import com.alewol.spring.securityjwtdemo.service.AppUserService;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping(ROOT)
@RequiredArgsConstructor
public class AppUserController {

    private final AppUserService userService;
    
    @GetMapping(USER + "getUsers")
    public ResponseEntity<List<AppUser>>getUsers(){
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @PostMapping(USER + "saveUser")
    public ResponseEntity<AppUser>saveUser(@RequestBody AppUser user){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path(ROOT + USER + "saveUser").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping(USER + "addRoleToUser")
    public ResponseEntity<Role>addRoleToUser(@RequestBody RoleToUserForm form){
        userService.addRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }

    @PostMapping(ROLE + "saveRole")
    public ResponseEntity<Role>saveRole(@RequestBody Role role){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path(ROOT + ROLE + "saveRole").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @GetMapping(TOKEN + "refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException{
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if(authorizationHeader != null && authorizationHeader.startsWith(HeaderPrefix))
        {
            try
            {
                String refresh_token = authorizationHeader.substring(HeaderPrefix.length());
                //TODO Refactor doublecated code in util class

                DecodedJWT decodedJWT= getDecodedJWT(refresh_token);
                String username = decodedJWT.getSubject();
                AppUser user = userService.getUser(username);
                

                String access_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(getAccessTokenTimeout())
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                .sign(jwtEncriptionAlgorithm);


                writeJwtJson(response, access_token, refresh_token);
            }
            catch (Exception exception) {
                checkAuthorizationHeaderException(response, exception);
            }
        }
        else {
            throw new RuntimeException("Refresh token is missing");
        }

    }
}


@Data
class RoleToUserForm {
    private String username;
    private String roleName;
}

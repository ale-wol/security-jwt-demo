package com.alewol.spring.securityjwtdemo.controller;

import java.net.URI;
import java.util.List;

import com.alewol.spring.securityjwtdemo.model.AppUser;
import com.alewol.spring.securityjwtdemo.model.Role;
import com.alewol.spring.securityjwtdemo.service.AppUserService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import static com.alewol.spring.securityjwtdemo.constants.Paths.ROOT;
import static com.alewol.spring.securityjwtdemo.constants.Paths.USER;
import static com.alewol.spring.securityjwtdemo.constants.Paths.ROLE;

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
}


@Data
class RoleToUserForm {
    private String username;
    private String roleName;
}

package com.alewol.spring.securityjwtdemo.controller;

import java.util.List;

import com.alewol.spring.securityjwtdemo.model.AppUser;
import com.alewol.spring.securityjwtdemo.service.AppUserService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("api/v1/user")
@RequiredArgsConstructor
public class AppUserController {

    private final AppUserService userService;
    
    @GetMapping("/getUsers")
    public ResponseEntity<List<AppUser>>getUsers(){
        return ResponseEntity.ok().body(userService.getUsers());
    }
}

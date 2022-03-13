package com.alewol.spring.securityjwtdemo.service;

import java.util.List;

import com.alewol.spring.securityjwtdemo.model.AppUser;
import com.alewol.spring.securityjwtdemo.model.Role;

public interface AppUserService {
    AppUser saveUser(AppUser user);
    
    Role saveRole(Role role);

    void addRoleToUser(String username, String rolename);

    AppUser getUser(String username);

    List<AppUser>getUsers();
}

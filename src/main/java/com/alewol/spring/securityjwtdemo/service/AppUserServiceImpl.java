package com.alewol.spring.securityjwtdemo.service;

import java.util.List;

import javax.transaction.Transactional;

import com.alewol.spring.securityjwtdemo.model.AppUser;
import com.alewol.spring.securityjwtdemo.model.Role;
import com.alewol.spring.securityjwtdemo.repo.RoleRepo;
import com.alewol.spring.securityjwtdemo.repo.AppUserRepo;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class AppUserServiceImpl implements AppUserService{

    private final AppUserRepo userRepo;
    private final RoleRepo roleRepo;

    @Override
    public AppUser saveUser(AppUser user) {
        log.info("Save User to " + user.getId() +  " Database");
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Sav Role to " + role.getId() +  " Database");
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String username, String rolename) {
        log.info("Adding role {} to user {}", rolename , username);
        AppUser user = userRepo.findByUsername(username);
        Role role = roleRepo.findByName(rolename);
        user.getRoles().add(role);
    }

    @Override
    public AppUser getUser(String username) {
        log.info("Fetching User {}", username);
        AppUser user = userRepo.findByUsername(username);
        return user;
    }

    @Override
    public List<AppUser> getUsers() {
        log.info("Fetching all Users");
        List<AppUser> userList =  userRepo.findAll();
        return userList;
    }
    
}

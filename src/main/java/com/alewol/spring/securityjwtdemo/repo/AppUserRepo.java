package com.alewol.spring.securityjwtdemo.repo;

import com.alewol.spring.securityjwtdemo.model.AppUser;

import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepo extends JpaRepository<AppUser, Long>{

    AppUser findByUsername(String username);
    
}

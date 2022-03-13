package com.alewol.spring.securityjwtdemo;

import java.util.ArrayList;

import com.alewol.spring.securityjwtdemo.model.AppUser;
import com.alewol.spring.securityjwtdemo.model.Role;
import com.alewol.spring.securityjwtdemo.service.AppUserService;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SecurityJwtDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityJwtDemoApplication.class, args);
	}

	@Bean
	CommandLineRunner run(AppUserService userService){
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));

			userService.saveUser(new AppUser(null, "Wolodymyr Selenskyj", "wolsel", "1234", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Luke Skywalker", "luksky", "1234", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Alice Cooper", "alicoo", "1234", new ArrayList<>()));

			userService.addRoleToUser("wolsel", "ROLE_USER");
			userService.addRoleToUser("wolsel", "ROLE_ADMIN");
			userService.addRoleToUser("luksky", "ROLE_USER");
			userService.addRoleToUser("luksky", "ROLE_ADMIN");
			userService.addRoleToUser("alicoo", "ROLE_USER");
		};
	}
}

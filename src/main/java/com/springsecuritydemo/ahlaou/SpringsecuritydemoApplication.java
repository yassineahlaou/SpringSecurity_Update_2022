package com.springsecuritydemo.ahlaou;

import com.springsecuritydemo.ahlaou.config.RsakeysConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@EnableConfigurationProperties(RsakeysConfig.class)
public class SpringsecuritydemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringsecuritydemoApplication.class, args);
	}

	/*@Bean
	CommandLineRunner start(UserService userService){
		return args->{
			userService.addNewRole(new Role(1L, "ADMIN"));
			userService.addNewRole(new Role(2L, "USER"));
			userService.addNewRole(new Role(3L, "COSTUMER_MANAGER"));

			userService.addNewUser((new User(1L , "yassine", "1234", new ArrayList<>())));
			userService.addNewUser((new User(2L , "lahoucine", "1234", new ArrayList<>())));
			userService.addNewUser((new User(3L , "admin", "1234", new ArrayList<>())));

			userService.addRoleToUser("yassine", "USER");
			userService.addRoleToUser("lahoucine", "COSTUMER_MANAGER");
			userService.addRoleToUser("admin", "ADMIN");





		};
	}*/
	@Bean
	public PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

}

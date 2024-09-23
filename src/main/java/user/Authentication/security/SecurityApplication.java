package user.Authentication.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import user.Authentication.security.entities.Role;
import user.Authentication.security.entities.User;
import user.Authentication.security.repository.UserRepository;

@SpringBootApplication
public class SecurityApplication implements CommandLineRunner {
@Autowired
private UserRepository userRepository;
	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	public void run(String... args){
		User adminAccount=userRepository.findByRole(Role.ADMIN);
		if(null == adminAccount){
			User user = new User();

			user.setEmail("admin@gmail.com");
			user.setFirstName("Admin");
			user.setLastName("admin");
			user.setRole(Role.ADMIN);
			user.setPassword(new BCryptPasswordEncoder().encode("admin"));
			userRepository.save(user);
		}
	}

}

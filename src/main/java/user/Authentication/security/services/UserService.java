package user.Authentication.security.services;

import org.springframework.security.core.userdetails.UserDetailsService;
import user.Authentication.security.repository.UserRepository;

public interface UserService {


    UserDetailsService userDetailsService();
}
package user.Authentication.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import user.Authentication.security.entities.Role;
import user.Authentication.security.entities.User;

import java.util.Optional;


@Repository
public interface UserRepository extends JpaRepository<User, Long>
{
    Optional<User> findByEmail(String email);

    User findByRole(Role role);


}
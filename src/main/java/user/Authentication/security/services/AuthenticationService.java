package user.Authentication.security.services;


import user.Authentication.security.dto.JwtAuthenticationResponse;
import user.Authentication.security.dto.RefreshTokenRequest;
import user.Authentication.security.dto.SignUpRequest;
import user.Authentication.security.dto.SigninRequest;
import user.Authentication.security.entities.User;

public interface AuthenticationService {
    User signup(SignUpRequest signUpRequest);
    JwtAuthenticationResponse signin(SigninRequest signinRequest);
    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}

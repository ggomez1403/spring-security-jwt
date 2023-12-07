package org.adaschool.api.controller.auth;

import org.adaschool.api.data.user.UserEntity;
import org.adaschool.api.data.user.UserService;
import org.adaschool.api.exception.InvalidCredentialsException;
import org.adaschool.api.security.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final UserService userService;

    private final JwtUtil jwtUtil;


    public AuthController(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping
    public ResponseEntity<TokenDto> login(@RequestBody LoginDto loginDto) {
        // 1. Find user by username
        String username = loginDto.getUsername();
        Optional<UserEntity> userOptional = userService.findByEmail(username);

        // 2. Validate user existence and password
        if (userOptional.isEmpty()) {
            throw new InvalidCredentialsException();
        }

        UserEntity user = userOptional.get();
        String passwordHash = user.getPasswordHash();
        if (!BCrypt.checkpw(loginDto.getPassword(), passwordHash)) {
            throw new InvalidCredentialsException();
        }

        // 3. Generate JWT token
        TokenDto tokenDto = jwtUtil.generateToken(username, user.getRoles());
        // 4. Return successful response with token
        return ResponseEntity.ok(tokenDto);
    }


}

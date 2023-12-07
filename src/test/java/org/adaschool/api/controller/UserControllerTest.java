package org.adaschool.api.controller;


import org.adaschool.api.controller.user.UserController;
import org.adaschool.api.controller.user.UserDto;
import org.adaschool.api.data.user.UserEntity;
import org.adaschool.api.data.user.UserService;
import org.adaschool.api.exception.UserWithEmailAlreadyRegisteredException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserControllerTest {

    @Mock
    private UserService userService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserController userController;


    @Test
    void getUserById_UserExists() {
        String userId = "123";
        UserEntity user = new UserEntity("User Name", "user@example.com", "hashedPassword");
        when(userService.findById(userId)).thenReturn(Optional.of(user));

        ResponseEntity<UserEntity> response = userController.getUserById(userId);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("user@example.com", response.getBody().getEmail());
    }

    @Test
    void getUserById_UserDoesNotExist() {
        String userId = "123";
        when(userService.findById(userId)).thenReturn(Optional.empty());

        ResponseEntity<UserEntity> response = userController.getUserById(userId);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    }

    @Test
    void createUser_NewUser() {
        UserDto userDto = new UserDto("New User", "new@example.com", "password");
        when(userService.findByEmail(userDto.getEmail())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(anyString())).thenReturn("hashedPassword");
        UserEntity userEntity = new UserEntity();
        when(userService.save(any())).thenReturn(userEntity);
        ResponseEntity<UserEntity> response = userController.createUser(userDto);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(userEntity, response.getBody());

    }

    @Test
    void createUser_EmailAlreadyExists() {
        UserDto userDto = new UserDto("New User", "existing@example.com", "password");
        when(userService.findByEmail(userDto.getEmail())).thenReturn(Optional.of(new UserEntity()));

        assertThrows(UserWithEmailAlreadyRegisteredException.class, () -> userController.createUser(userDto));
    }

    @Test
    void deleteUser_UserExists() {
        String userId = "123";
        when(userService.findById(userId)).thenReturn(Optional.of(new UserEntity()));

        ResponseEntity<Boolean> response = userController.deleteUser(userId);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(Boolean.TRUE, response.getBody());

        verify(userService).delete(any(UserEntity.class));
    }

    @Test
    void deleteUser_UserDoesNotExist() {
        String userId = "123";
        when(userService.findById(userId)).thenReturn(Optional.empty());

        ResponseEntity<Boolean> response = userController.deleteUser(userId);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotEquals(Boolean.TRUE, response.getBody());
    }
}

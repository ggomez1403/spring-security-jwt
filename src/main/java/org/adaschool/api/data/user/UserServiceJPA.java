package org.adaschool.api.data.user;

import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 *
 */
@Service
public class UserServiceJPA implements UserService {

    final UserRepository userRepository;


    public UserServiceJPA(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Optional<UserEntity> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public Optional<UserEntity> findById(String id) {
        return userRepository.findById(Long.parseLong(id));
    }

    @Override
    public UserEntity save(UserEntity user) {
        return userRepository.save(user);
    }

    @Override
    public void delete(UserEntity user) {
        userRepository.delete(user);
    }


}

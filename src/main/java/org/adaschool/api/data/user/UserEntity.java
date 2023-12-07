package org.adaschool.api.data.user;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Entity(name = "UsersTable")
public class UserEntity {

    @GeneratedValue(strategy = GenerationType.AUTO)
    @Id
    private Long id;
    private String name;
    private String email;
    private String passwordHash;
    private List<UserRoleEnum> roles;

    public UserEntity() {

    }

    public UserEntity(String name, String email, String passwordHash) {
        this.name = name;
        this.email = email;
        this.passwordHash = passwordHash;
        roles = new ArrayList<>(Collections.singleton(UserRoleEnum.USER));
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public List<UserRoleEnum> getRoles() {
        return roles;
    }

    public void addRole(UserRoleEnum role) {
        if (!roles.contains(role)) {
            roles.add(role);
        }
    }
}

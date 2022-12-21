package com.springsecuritydemo.ahlaou.repositories;

import com.springsecuritydemo.ahlaou.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RolesRepository extends JpaRepository<Role, Long> {
    public Role findByRoleName(String roleName);
}

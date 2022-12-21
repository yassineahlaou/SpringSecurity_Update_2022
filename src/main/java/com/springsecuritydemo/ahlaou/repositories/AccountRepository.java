package com.springsecuritydemo.ahlaou.repositories;

import com.springsecuritydemo.ahlaou.models.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AccountRepository extends JpaRepository<Account, Long> {
    public Account findByusername(String username);
}

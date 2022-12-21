package com.springsecuritydemo.ahlaou.service;

import com.springsecuritydemo.ahlaou.models.Account;
import com.springsecuritydemo.ahlaou.models.Role;
import com.springsecuritydemo.ahlaou.repositories.RolesRepository;
import com.springsecuritydemo.ahlaou.repositories.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;


@Service
@Transactional
public class AccountServiceImp implements AccountService {
    @Autowired
    private AccountRepository accountRepository;
    @Autowired
    private RolesRepository rolesRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Override
    public Account addNewAccount(Account newAccount) {
       String pass =  newAccount.getPassword();
       newAccount.setPassword(passwordEncoder.encode(pass));
       return accountRepository.save(newAccount);
    }

    @Override
    public Role addNewRole(Role newRole) {
        return rolesRepository.save(newRole);
    }

    @Override
    public void addRoleToAccount(String username, String roleName) {
        Account foundAccount = accountRepository.findByusername(username);
        Role foundRole = rolesRepository.findByRoleName(roleName);
        foundAccount.getAccountRoles().add(foundRole);
    }

    @Override
    public Account loadAccountByUsername(String username) {
        return accountRepository.findByusername(username);
    }

    @Override
    public List<Account> listAccounts() {
        return accountRepository.findAll();
    }
}

package com.springsecuritydemo.ahlaou.service;

import com.springsecuritydemo.ahlaou.models.Account;
import com.springsecuritydemo.ahlaou.models.Role;

import java.util.List;

public interface AccountService {

    Account addNewAccount(Account newAccount);
    Role addNewRole (Role newRole);
    void addRoleToAccount (String username , String roleName);
    Account loadAccountByUsername (String username);
    List<Account> listAccounts();

}

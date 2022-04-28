package com.example.sts.service;

import com.example.sts.eo.ERole;
import com.example.sts.model.Account;
import com.example.sts.model.Role;
import com.example.sts.repository.AccountRepository;
import com.example.sts.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Arrays;
import java.util.HashSet;

public class UserService {

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public Account getUserByEmail(String email) {
        return accountRepository.findByEmail(email);
    }

    public Account getUserByUsername(String username) {
        return accountRepository.findByUsername(username);
    }

    public Account setUser(Account user) throws Exception{
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setActive(true);
        Role userRole = null;
        if(user.getUsername().equals("admin")) {
            userRole = roleRepository.findByRole(ERole.ADMIN.getValue());
        } else if(user.getUsername().equals("user")) {
            userRole = roleRepository.findByRole(ERole.MANAGER.getValue());
        } else {
            userRole = roleRepository.findByRole(ERole.GUEST.getValue());
        }
        user.setRoles(new HashSet<Role>(Arrays.asList(userRole)));
        return accountRepository.save(user);
    }
}

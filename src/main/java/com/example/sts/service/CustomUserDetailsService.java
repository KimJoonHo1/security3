package com.example.sts.service;

import com.example.sts.model.Account;
import com.example.sts.model.Role;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.annotation.Resource;
import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CustomUserDetailsService implements UserDetailsService {
    protected Logger log = LoggerFactory.getLogger(this.getClass());
    @Resource
    private UserService userService;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("[ykson] call the loadUserByUsername()");
        Account user = null;
        try {
            user = userService.getUserByUsername(username);
        } catch(Exception e) {
            log.error(e.getMessage());
            throw new UsernameNotFoundException(e.getMessage());
        }

        return buildUserForAuthentication(user, getUserAuthority(user.getRoles()));
    }

    private List<GrantedAuthority> getUserAuthority(Set<Role> userRole) {
        Set<GrantedAuthority> roles = new HashSet<GrantedAuthority>();
        for(Role role : userRole) {
            roles.add(new SimpleGrantedAuthority(role.getRole()));
        }
        List<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>(roles);

        return grantedAuthorities;
    }

    private UserDetails buildUserForAuthentication(Account user, List<GrantedAuthority> authorities) {
        return new User(user.getUsername(), user.getPassword(), user.isActive(), true, true, true, authorities);
    }
}

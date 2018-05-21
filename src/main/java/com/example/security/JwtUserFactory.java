package com.example.security;

import java.util.Collection;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.example.model.Role;
import com.example.model.User;


public final class JwtUserFactory {

    private JwtUserFactory() {
    }

    public static JwtUser create(User user) {
        return new JwtUser(user.getId(), user.getEmail(), user.getName(), user.getLastName(), 
        		user.getEmail(), user.getPassword(), mapToGrantedAuthorities(user.getRoles()), true, new Date());
    }

    private static Collection<GrantedAuthority> mapToGrantedAuthorities(Set<Role> authorities) {
        return authorities.stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getRole()))
                .collect(Collectors.toList());
    }
}

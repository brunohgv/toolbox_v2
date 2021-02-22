package com.brunohgv.toolbox.auth.services;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return new User("user", "$2a$10$Hc.KN9eoX/KhWCIuxGnmqOvDTh5JBCXJ0y9nWa6mKXH/vwic0mrOm", new ArrayList<>());
    }
}

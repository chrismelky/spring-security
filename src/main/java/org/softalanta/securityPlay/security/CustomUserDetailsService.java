package org.softalanta.securityPlay.security;

import org.softalanta.securityPlay.UserRepository;
import org.softalanta.securityPlay.domain.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Autowired
    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        User user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail).orElseThrow(()->new UsernameNotFoundException("User not found"));
       return UserPrincipal.create(user);
    }

    public UserDetails getById(Long userId) {
        User user = userRepository.findById(userId).orElseThrow(()-> new UsernameNotFoundException("User not found"));
       return UserPrincipal.create(user);
    }
}

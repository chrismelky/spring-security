package org.softalanta.securityPlay.controller;

import org.softalanta.securityPlay.UserRepository;
import org.softalanta.securityPlay.domain.LoginDetail;
import org.softalanta.securityPlay.domain.User;
import org.softalanta.securityPlay.security.TokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class UserController {

    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    private final TokenProvider tokenProvider;

    private final AuthenticationManager authenticationManager;

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserController(OAuth2AuthorizedClientService oAuth2AuthorizedClientService, TokenProvider tokenProvider, AuthenticationManager authenticationManager, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.oAuth2AuthorizedClientService = oAuth2AuthorizedClientService;
        this.tokenProvider = tokenProvider;
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }


    @GetMapping("/userInfo")
    public OAuth2AuthorizedClient getUserInfo(OAuth2AuthenticationToken authenticationToken){
        OAuth2AuthorizedClient client = oAuth2AuthorizedClientService
                .loadAuthorizedClient(authenticationToken.getAuthorizedClientRegistrationId(),authenticationToken.getName());

        return client;
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginDetail login){
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        login.getUsernameOrEmail(),
                        login.getPassword()
                ));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = tokenProvider.createToken(authentication);

        return ResponseEntity.ok(token);
    }

    @PostMapping("/signup")
    public ResponseEntity<User> signUp(@RequestBody User user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        User user1 = userRepository.save(user);
        return ResponseEntity.ok(user1);
    }


}

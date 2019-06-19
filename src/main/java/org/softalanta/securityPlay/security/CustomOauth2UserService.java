package org.softalanta.securityPlay.security;

import org.softalanta.securityPlay.UserRepository;
import org.softalanta.securityPlay.domain.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private  UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        String email =oAuth2User.getAttributes().get("email").toString();
        Optional<User> result = userRepository.findByUsernameOrEmail(email, email);
        User user;
        if(result.isPresent()){
            user= result.get();
        }
        else{
            user = new User();
        }
        user.setEmail(email);

        return UserPrincipal.create(userRepository.save(user), oAuth2User.getAttributes() );
    }

}

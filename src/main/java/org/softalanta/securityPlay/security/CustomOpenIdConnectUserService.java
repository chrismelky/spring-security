package org.softalanta.securityPlay.security;

import org.softalanta.securityPlay.UserRepository;
import org.softalanta.securityPlay.domain.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomOpenIdConnectUserService extends OidcUserService {

    @Autowired
    private  UserRepository userRepository;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);
        String email =oidcUser.getAttributes().get("email").toString();
        Optional<User> result = userRepository.findByUsernameOrEmail(email, email);
        User user;
        if(result.isPresent()){
            user= result.get();
        }
        else{
            user = new User();
        }
        user.setEmail(email);

        return UserPrincipal.create(userRepository.save(user), oidcUser.getClaims(), oidcUser.getUserInfo(), oidcUser.getIdToken());
    }

}

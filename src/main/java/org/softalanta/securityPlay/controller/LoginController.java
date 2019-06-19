package org.softalanta.securityPlay.controller;

import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.HashMap;
import java.util.Map;

@Controller
public class LoginController {


    @GetMapping("/login")
    public String loginPage(Model model){

       ClientRegistration clientRegistration = CommonOAuth2Provider.GOOGLE.getBuilder("google")
                .clientId("696666858656-qkjnjvkvgg619odd03l31g9ffikt493l.apps.googleusercontent.com")
                .clientSecret("uWvPd9cSdpxO29reKjYE5vAg")
                .build();
        Map<String, String> urls = new HashMap<>();
        urls.put(clientRegistration.getClientName(),"/oauth2/authorize/"+clientRegistration.getRegistrationId());
        model.addAttribute("urls", urls);
        return "login";
    }
}

package org.softalanta.securityPlay.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/")
    public String home(){
        return "home";
    }
}

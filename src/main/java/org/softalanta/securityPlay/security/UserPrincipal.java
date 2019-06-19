package org.softalanta.securityPlay.security;

import org.softalanta.securityPlay.domain.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class UserPrincipal implements OAuth2User, UserDetails, OidcUser {

    private Long id;
    private String username;
    private String email;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attributes;
    private OidcIdToken oidcIdToken;
    private OidcUserInfo oidcUserInfo;
    private Map<String, Object> claims;



    public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    public UserPrincipal(){
        super();
    }

    public UserPrincipal(Long id, String email, String password, Collection<? extends GrantedAuthority> authorities){


        this.id = id;
        this.username = email;
        this.email = email;
        this.password = password;
        this.authorities = authorities;
    }

    public static UserPrincipal create(User user){
        List<GrantedAuthority> authorities = Collections.
                singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        return new UserPrincipal(user.getId(),  user.getEmail(), user.getPassword(),authorities);
    }

    public static UserPrincipal create(User user, Map<String, Object> attributes) {
        UserPrincipal userPrincipal = UserPrincipal.create(user);
        userPrincipal.setAttributes(attributes);
        return userPrincipal;
    }

    public static UserPrincipal create(User user, Map<String, Object> claims, OidcUserInfo userInfo, OidcIdToken oidcIdToken) {
        UserPrincipal userPrincipal = UserPrincipal.create(user);
        userPrincipal.claims = claims;
        userPrincipal.oidcUserInfo = userInfo;
        userPrincipal.oidcIdToken = oidcIdToken;
        return userPrincipal;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Map<String, Object> getAttributes() {

        return attributes;
    }
    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    public String getName() {
        return String.valueOf(id);
    }

    @Override
    public Map<String, Object> getClaims() {
        return this.claims;
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return this.oidcUserInfo;
    }

    @Override
    public OidcIdToken getIdToken() {
        return this.oidcIdToken;
    }
}

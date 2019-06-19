package org.softalanta.securityPlay.security;

import io.jsonwebtoken.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class TokenProvider {

    public String createToken(Authentication authentication){
//      1. Get Authenticated user
        UserPrincipal userPrincipal= (UserPrincipal) authentication.getPrincipal();

//      2. Create exparation date
        return createToken(userPrincipal);
    }

    public String createToken(UserPrincipal userPrincipal){
        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + 600000);

        return Jwts.builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS256,"12345")
                .compact();
    }

    public Long getUserId(String token){
        Claims claim = Jwts.parser().setSigningKey("12345").parseClaimsJws(token).getBody();
        return Long.parseLong(claim.getSubject());
    }

    public boolean validateToken(String token){
        try {
           Jwts.parser().setSigningKey("12345").parseClaimsJws(token);
           return true;
        } catch (SignatureException ex) {
            System.out.println("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            System.out.println("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            System.out.println("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            System.out.println("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            System.out.println("JWT claims string is empty.");
        } catch (Exception ex){
            System.out.println(ex.getLocalizedMessage());

        }
        return false;
    }
}

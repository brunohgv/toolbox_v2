package com.brunohgv.toolbox.auth.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
@PropertySource("classpath:application.properties")
public class JwtUtils {
    private static final long EXPIRATION_TIME_IN_MILLIS = 24 * 60 * 60 * 1000;

    @Value("${jwt.secret.env.variable}")
    private String jwtSecretEnvVariable;


    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        String jwtSecret = System.getenv(this.jwtSecretEnvVariable);
        return Jwts.builder()
                .addClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME_IN_MILLIS))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        String username = this.extractUsername(token);
        Boolean userMatches = userDetails.getUsername().equals(username);
        Boolean tokenIsNotExpired = !this.isTokenExpired(token);
        return userMatches && tokenIsNotExpired;
    }

    public Boolean isTokenExpired(String token) {
        return this.getClaims(token).getExpiration().before(new Date());
    }

    public String extractUsername(String token) {
        return this.getClaims(token).getSubject();
    }

    private Claims getClaims(String token) {
        return Jwts.parser().setSigningKey(jwtSecretEnvVariable).parseClaimsJws(token).getBody();
    }
}

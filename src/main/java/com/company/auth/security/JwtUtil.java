package com.company.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

import javax.crypto.SecretKey;

@Component
public class JwtUtil {

    private static final long EXPIRATION_TIME = 1000 * 60 * 60; // 1 hour

    // MUST be 32+ chars (256 bits)
    private static final String SECRET =
            "THIS_IS_A_VERY_LONG_AND_SECURE_SECRET_KEY_256_BITS_MINIMUM";

    private final SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes());

    // 🔐 Generate JWT
    public String generateToken(String username) {
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(key) // ✅ correct for jjwt 0.12+
                .compact();
    }

    // 🔍 Extract username from JWT
    public String extractUsername(String token) {

        Claims claims = Jwts.parser()
                .verifyWith(key)          // ✅ new API
                .build()
                .parseSignedClaims(token) // ✅ parses signed JWT
                .getPayload();

        return claims.getSubject();
    }
}

package com.rjproj.memberapp.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;

@Service
public class JWTUtil {

    @Value("${jwt.secret}")
    private String jwtSecretKey;

    @Value("${jwt.expiration}")
    private long jwtExpirationTime;

    private String token;

    public String extractUsername(String token) {
        Claims claims = extractAllClaims(token);
        return claims.getSubject();
    }

    public Date extractExpiration(String token) {
        return extractAllClaims(token).getExpiration();
    }

    public List<String> extractPermissions(String token) {
        Claims claims = extractAllClaims(token);
        Object permissions = claims.get("permissions");

        // Check if the permissions claim is indeed a List
        if (permissions instanceof List<?>) {
            // Check if the list contains only strings
            List<?> permissionsList = (List<?>) permissions;
            if (permissionsList.stream().allMatch(item -> item instanceof String)) {
                @SuppressWarnings("unchecked") // Suppress warning after ensuring type safety
                List<String> permissionsStrings = (List<String>) permissionsList;
                return permissionsStrings;
            }
        }
        return Collections.emptyList(); // Return an empty list if no valid permissions are found
    }

    public UUID extractSelectedOrganizationId(String token) {
        Claims claims = extractAllClaims(token);
        Object selectedOrganizationId = claims.get("selectedOrganizationId");
        if (selectedOrganizationId instanceof String) {
            return UUID.fromString((String) selectedOrganizationId);
        }
        return null; // Handle the case where the value is not a String
    }

    public UUID extractMemberId(String token) {
        Claims claims = extractAllClaims(token);
        Object memberId = claims.get("memberId");
        if (memberId instanceof String) {
            return UUID.fromString((String) memberId);
        }
        throw new IllegalArgumentException("Invalid memberId in token");
    }

    public UUID extractMemberIdInternally() {
        Claims claims = extractAllClaims(this.token);
        Object memberId = claims.get("memberId");
        if (memberId instanceof String) {
            return UUID.fromString((String) memberId);
        }
        throw new IllegalArgumentException("Invalid memberId in token");
    }

    public String getToken() {
        return token;
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecretKey.getBytes());
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Boolean validateToken(String token) {
        return !isTokenExpired(token);
    }
}
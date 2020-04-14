package dev.sanda.authentifi.security.jwt;

import dev.sanda.authentifi.config.AuthenticationServerConfiguration;
import dev.sanda.authentifi.security.AES;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {
    @Autowired
    private AuthenticationServerConfiguration config;
    @Autowired
    private AES aes;

    public Cookie createAccessTokenCookie(String username, Collection<? extends GrantedAuthority> authorities, HttpServletRequest request) {
        val roles = authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        val claims = Jwts.claims().setSubject(username);
        claims.put("roles", roles);
        val now = new Date();
        val notBefore = new Date(now.getTime() - 1);
        val exp = new Date(now.getTime() + config.jwtTtlInMs());
        val token = generateEncryptedToken(claims, exp, notBefore);
        val accessTokenCookie = new Cookie("access_token", token);
        accessTokenCookie.setMaxAge(Math.toIntExact(exp.getTime() - now.getTime())/1000);
        setCommonCookieProperties(request, accessTokenCookie);
        return accessTokenCookie;
    }

    private String generateEncryptedToken(Claims claims, Date exp, Date notBefore) {
        return aes.encrypt(
                Jwts.builder()
                .setClaims(claims)
                .setNotBefore(notBefore)
                .setIssuedAt(new Date())
                .setExpiration(exp)
                .signWith(SignatureAlgorithm.HS256, config.jwtSigningSecret())
                .compact()
        );
    }
    @Transactional
    public Authentication getAuthentication(String token) {
        val userDetails = config.userDetailsService().loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public String getUsername(String token) {
        return Jwts.parser().setSigningKey(config.jwtSigningSecret()).parseClaimsJws(token).getBody().getSubject();
    }

    public String resolveAndValidateToken(HttpServletRequest request, HttpServletResponse response) {
        String accessTokenValue, refreshTokenValue;
        if((accessTokenValue = resolveDecryptedTokenCookie(request, "access_token")) != null &&
            isValidToken(accessTokenValue))
            return accessTokenValue;
        if((refreshTokenValue = resolveDecryptedTokenCookie(request, "refresh_token")) != null &&
            isValidToken(refreshTokenValue)) {
            val userDetails = config.userDetailsService().loadUserByUsername(getUsername(refreshTokenValue));
            if(userDetails == null) throw new BadCredentialsException("Invalid refresh token - please login again");
            val accessTokenCookie = createAccessTokenCookie(userDetails.getUsername(), userDetails.getAuthorities(), request);
            response.addCookie(accessTokenCookie);
            addRefreshTokenCookieIfEnabled(userDetails.getUsername(), true, request, response);
            return aes.decrypt(accessTokenCookie.getValue());
        }
        return null;
    }

    private String resolveDecryptedTokenCookie(HttpServletRequest req, String name) {
        val cookies = req.getCookies();
        if(cookies == null) return null;
        for(val cookie : cookies)
            if(cookie.getName().equals(name))
                return aes.decrypt(cookie.getValue());
        return null;
    }

    public boolean isValidToken(String token) {
        try {
            val claims = Jwts.parser().setSigningKey(config.jwtSigningSecret()).parseClaimsJws(token);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidJwtAuthenticationException("Expired or invalid JWT token");
        }
    }

    public void addRefreshTokenCookieIfEnabled(String username, boolean rememberMe, HttpServletRequest request, HttpServletResponse res) {
        if(!(config.rememberMeEnabled() && rememberMe)) return;
        val claims = Jwts.claims().setSubject(username);
        val now = new Date();
        val notBefore = new Date(now.getTime() + config.jwtTtlInMs());
        val exp = new Date(notBefore.getTime() + config.rememberMeExpInSeconds()*1000);
        val token = generateEncryptedToken(claims, exp, notBefore);
        val refreshTokenCookie = new Cookie("refresh_token", aes.encrypt(token));
        refreshTokenCookie.setMaxAge(config.rememberMeExpInSeconds());
        setCommonCookieProperties(request, refreshTokenCookie);
        res.addCookie(refreshTokenCookie);
    }

    private void setCommonCookieProperties(HttpServletRequest request, Cookie cookie) {
        val domain = request
                        .getHeader("origin")
                        .replaceFirst("http[s]?://", "")
                        .replaceFirst(":.+", "");
        if(domain.equals("localhost")) cookie.setDomain("127.0.0.1");
        else cookie.setDomain(domain);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
    }
}

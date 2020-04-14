package dev.sanda.authentifi.web.controller;


import dev.sanda.authentifi.config.AuthenticationServerConfiguration;
import dev.sanda.authentifi.security.jwt.JwtTokenProvider;
import dev.sanda.authentifi.web.dto.AuthenticationRequest;
import dev.sanda.authentifi.web.dto.DirectSignupRequest;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

import static org.springframework.http.ResponseEntity.ok;

@RestController
public class AuthenticationController {
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    private AuthenticationServerConfiguration config;

    @PostMapping("/auth/signin")
    public void signin(@RequestBody AuthenticationRequest authRequest, HttpServletRequest request, HttpServletResponse response) {
        try {
            //get username & password
            val username = authRequest.getUsername();
            val password = authRequest.getPassword();
            // validate credentials
            config.authenticationManager().authenticate(new UsernamePasswordAuthenticationToken(username, password));
            // load user details
            val userDetails = config.userDetailsService().loadUserByUsername(username);
            if(userDetails == null) throw new UsernameNotFoundException("Username " + username + " not found");
            // assign access token
            response.addCookie(jwtTokenProvider.createAccessTokenCookie(username, userDetails.getAuthorities(), request));
            // handle remember me
            jwtTokenProvider.addRefreshTokenCookieIfEnabled(username, authRequest.isRememberMe(), request, response);
            // all good!
            response.setStatus(200);
        } catch (AuthenticationException e) {
            // looks like you're SOL...
            response.setStatus(401);
            throw new BadCredentialsException("Invalid username/password supplied");
        }
    }

    @PostMapping("/auth/signup")
    public void directSignup(@RequestBody DirectSignupRequest signupRequest, HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        try {
            config.handleDirectSignup(signupRequest, request, response);
            response.setStatus(200);
        } catch (Exception e) {
            response.sendError(400, "Fatal error during sign up process: " + e.getMessage());
        }
    }

    @GetMapping("/auth/invitation-signup")
    private void invitationSignup(@RequestParam String inviteToken, HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        try {
            config.handleInvitedSignup(inviteToken, request, response);
            response.setStatus(200);
        }catch (Exception e){
            response.sendError(400, "Fatal error during sign up process: " + e.getMessage());
        }
    }

    @PostMapping("/auth/create-new-invite")
    public ResponseEntity<String> createNewInvite(@RequestBody List<String> proposedAuthorities, HttpServletRequest request, HttpServletResponse response) {
        try {
            val token = config.createNewUserInvite(proposedAuthorities, request, response);
            return ok(request.getHeader("origin") + "/auth/invitation-signup?inviteToken=" + token);
        }catch (Exception e){
            return ResponseEntity.badRequest().body("Fatal error during invite process: " + e.getMessage());
        }
    }
}



















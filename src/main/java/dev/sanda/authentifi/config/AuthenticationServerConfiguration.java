package dev.sanda.authentifi.config;


import dev.sanda.jwtauthtemplate.web.dto.DirectSignupRequest;
import dev.sanda.jwtauthtemplate.web.exceptions.InvalidInviteAttemptException;
import dev.sanda.jwtauthtemplate.web.exceptions.InvalidSignupException;
import dev.sanda.jwtauthtemplate.web.exceptions.NotImplementedException;
import lombok.val;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;

@Component
public interface AuthenticationServerConfiguration {

    byte[] jwtSigningSecret();
    UserDetailsService userDetailsService();
    String aesSecretKey();
    String aesSalt();

    default AuthenticationManager authenticationManager(){
        return authentication -> {
            val userDetails = (UserDetails) authentication.getPrincipal();
            val loadedUserDetails = userDetailsService().loadUserByUsername(userDetails.getUsername());
            if(loadedUserDetails == null)
                throw new UsernameNotFoundException("Cannot find user with username: " + userDetails.getUsername());
            if(!new BCryptPasswordEncoder().matches(userDetails.getPassword(), loadedUserDetails.getPassword()))
                throw new BadCredentialsException("Invalid username / password supplied");
            return new UsernamePasswordAuthenticationToken(
                    loadedUserDetails,
                    "",
                    loadedUserDetails.getAuthorities()
            );
        };
    }

    default Long jwtTtlInMs(){
        return 3600L; // 1 hour
    }

    default Boolean rememberMeEnabled(){
        return true;
    }
    default Integer rememberMeExpInSeconds(){
        return 120960000; // 2 weeks
    }

    default List<String> allowedOrigins(){
        return new ArrayList<>();
    }

    default String[] publicUrls(){
        return new String[]{};
    }

    default void handleDirectSignup(DirectSignupRequest directSignupRequest, HttpServletRequest request, HttpServletResponse response) throws InvalidSignupException{
        throw new NotImplementedException();
    }

    default void handleInvitedSignup(String inviteToken, HttpServletRequest request, HttpServletResponse response) throws InvalidSignupException{
        throw new NotImplementedException();
    }

    default String createNewUserInvite(List<String> proposedAuthorities, HttpServletRequest request, HttpServletResponse response) throws InvalidInviteAttemptException{
        throw new NotImplementedException();
    }
}

package dev.sanda.authentifi.config;


import dev.sanda.authentifi.web.dto.DirectSignupRequest;
import dev.sanda.authentifi.web.exceptions.InvalidInviteAttemptException;
import dev.sanda.authentifi.web.exceptions.InvalidSignupException;
import dev.sanda.authentifi.web.exceptions.NotImplementedException;
import lombok.val;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

@Component
public interface AuthenticationServerConfiguration {

    byte[] jwtSigningSecret();
    UserDetailsService userDetailsService();
    String aesSecretKey();
    String aesSalt();

    default AuthenticationManager authenticationManager(){
        return authentication -> {
            val username = (String) authentication.getPrincipal();
            val loadedUserDetails = userDetailsService().loadUserByUsername(username);
            if(loadedUserDetails == null)
                throw new UsernameNotFoundException("Cannot find user with username: " + username);
            if(!new BCryptPasswordEncoder().matches((CharSequence) authentication.getCredentials(), loadedUserDetails.getPassword()))
                throw new BadCredentialsException("Invalid username / password supplied");
            return new UsernamePasswordAuthenticationToken(
                    loadedUserDetails,
                    "",
                    loadedUserDetails.getAuthorities()
            );
        };
    }

    default Long jwtTtlInMs(){
        return 3600000L; // 1 hour
    }

    default Boolean rememberMeEnabled(){
        return true;
    }
    default Integer rememberMeExpInSeconds(){
        return 1209600; // 2 weeks
    }

    default CorsConfigurationSource corsConfigurationSource(){
        return null;
    }

    default boolean enableCors(){
        return false;
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

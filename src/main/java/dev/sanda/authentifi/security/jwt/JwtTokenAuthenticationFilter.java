package dev.sanda.authentifi.security.jwt;


import lombok.AllArgsConstructor;
import lombok.val;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@AllArgsConstructor
public class JwtTokenAuthenticationFilter extends GenericFilterBean {
    private JwtTokenProvider jwtTokenProvider;
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain)
        throws IOException, ServletException {
        val token = jwtTokenProvider.resolveAndValidateToken((HttpServletRequest) req, (HttpServletResponse) res);
        if (token != null) {
            val auth = jwtTokenProvider.getAuthentication(token);
            if (auth != null) SecurityContextHolder.getContext().setAuthentication(auth);
        }
        filterChain.doFilter(req, res);
    }
}

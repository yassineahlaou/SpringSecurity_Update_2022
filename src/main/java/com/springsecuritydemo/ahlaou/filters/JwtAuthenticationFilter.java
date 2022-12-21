package com.springsecuritydemo.ahlaou.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.crypto.impl.HMAC;
import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;
    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JwtDecoder jwtDecoder, JwtEncoder jwtEncoder){
        this.authenticationManager = authenticationManager;
        this.jwtDecoder = jwtDecoder;
        this.jwtEncoder = jwtEncoder;

    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        System.out.println(username);
        System.out.println(password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authenticationToken);

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("Success Auth");
        User user = (User) authResult.getPrincipal();
        Instant instant = Instant.now();
        Map<String, String> idToken = new HashMap<>();
        String scope  = user.getAuthorities()
                .stream().map(auth->auth.getAuthority())
                .collect(Collectors.joining(" "));
        //Access Token
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .subject(user.getUsername())
                .issuer("spring_security")
                .expiresAt(instant.plus(1, ChronoUnit.MINUTES))
                .issuedAt(instant)
                .claim("scope", scope)
                .build();
        String jwtAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        //Refresh Token
        JwtClaimsSet jwtClaimsRefreshSet = JwtClaimsSet.builder()
                .subject(user.getUsername())
                .issuer("spring_security")
                .expiresAt(instant.plus(5, ChronoUnit.MINUTES))
                .issuedAt(instant)
                //.claim("scope", scope) no need for roles here, ust a refresh token , if the access token expires
                .build();
        String jwtRefreshToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsRefreshSet)).getTokenValue();
        idToken.put("accessToken", jwtAccessToken);
        idToken.put("refreshToken" , jwtRefreshToken);
        //output idToken in response in json format
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(), idToken);


    }
}

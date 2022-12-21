package com.springsecuritydemo.ahlaou.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.springsecuritydemo.ahlaou.models.Account;
import com.springsecuritydemo.ahlaou.models.Role;
import com.springsecuritydemo.ahlaou.models.RoleAccountBody;
import com.springsecuritydemo.ahlaou.service.AccountService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AuthenticationController {
    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;
    private AuthenticationManager authenticationManager;
    private UserDetailsService userDetailsService;

    private AccountService accountService;

    public AuthenticationController(JwtEncoder jwtEncoder, AuthenticationManager authenticationManager, JwtDecoder jwtDecoder, UserDetailsService userDetailsService, AccountService accountService){
        this.jwtEncoder = jwtEncoder;
        this.authenticationManager = authenticationManager ;
        this.jwtDecoder = jwtDecoder;
        this.userDetailsService = userDetailsService;
        this.accountService = accountService;
    }

    @GetMapping("/allAccounts")
    public List<Account> getAllAccounts(){
        return accountService.listAccounts();
    }

    @PostMapping("/addAccount")
    public Account addNewAccount(@RequestBody Account account){
        return accountService.addNewAccount(account);
    }
    @PostMapping("/addRole")
    public Role addNewRole(@RequestBody Role role){
        return accountService.addNewRole(role);
    }
    @PostMapping("/addRoleToAccount")
    public void addRoleToUser(@RequestBody RoleAccountBody roleAccountBody){
        accountService.addRoleToAccount(roleAccountBody.getUsername(), roleAccountBody.getRoleName());
    }

    @GetMapping("/refreshToken")
    public ResponseEntity<Map<String, String>> refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authToken  = request.getHeader("Authorization");

        if (authToken!= null && authToken.startsWith("Bearer ")){
            String jwt = authToken.substring(7);
            Jwt decodeJWT = null;
            try {
                decodeJWT = jwtDecoder.decode(jwt);
            } catch (JwtException e) {

                /*response.setHeader("error" , e.getMessage());
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(), e.getMessage());*/
                return new ResponseEntity<>(Map.of("error-message" , e.getMessage()), HttpStatus.UNAUTHORIZED);
            }
            String username = decodeJWT.getSubject();
            Account account = accountService.loadAccountByUsername(username);
            String scope  = account.getAccountRoles()
                    .stream().map(auth->auth.getRoleName())
                    .collect(Collectors.joining(" "));
            Instant instant = Instant.now();
            Map<String, String> idToken = new HashMap<>();
            JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                    .subject(account.getUsername())
                    .issuer("spring_security")
                    .expiresAt(instant.plus(1, ChronoUnit.MINUTES))
                    .issuedAt(instant)
                    .claim("scope", scope)
                    .build();
            String jwtAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
            JwtClaimsSet jwtClaimsRefreshSet = JwtClaimsSet.builder()
                    .subject(account.getUsername())
                    .issuer("spring_security")
                    .expiresAt(instant.plus(5, ChronoUnit.MINUTES))
                    .issuedAt(instant)
                    //.claim("scope", scope) no need for roles here, ust a refresh token , if the access token expires
                    .build();
            String jwtRefreshToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsRefreshSet)).getTokenValue();
            idToken.put("accessToken", jwtAccessToken);
            idToken.put("refreshToken" , jwtRefreshToken);
            //output idToken in response in json format
            /*response.setContentType("application/json");
            new ObjectMapper().writeValue(response.getOutputStream(), idToken);*/
            return new ResponseEntity<>(Map.of("access-token" , jwtAccessToken,
                                                    "refresh-token", jwtRefreshToken), HttpStatus.OK);


        }else{

            /*response.setContentType("application/json");
            new ObjectMapper().writeValue(response.getOutputStream(), "Please Provide a valid refreshToken");*/
            return new ResponseEntity<>(Map.of("error-message" , "Please provide a valide refresh toekn") , HttpStatus.UNAUTHORIZED);
        }
    }
    @PostMapping("/token")
    //public Map<String, String> jwtToken (Authentication authentication){
    public ResponseEntity<Map<String, String>> jwtToken (String grantType, String username, String password, boolean withRefreshToken, String refreshToken){
        //2 things we need to generate tokens
        String subject = null;
        String scope = null;

        if (grantType.equals("password")){
            //manual authentication
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            subject = authentication.getName();
            scope = authentication.getAuthorities()
                    .stream().map(auth->auth.getAuthority())
                    .collect(Collectors.joining(" "));//delimiter should be an empty space so we got each authority in a separete object
        }else if (grantType.equals("refreshToken")){
            if (refreshToken == null){
                return  new ResponseEntity<>(Map.of("message", "RefreshToken is required"), HttpStatus.UNAUTHORIZED);            }
            Jwt decodeJWT = null;
            try {
                decodeJWT = jwtDecoder.decode(refreshToken);
            } catch (JwtException e) {
                return new ResponseEntity<>(Map.of("message", e.getMessage()), HttpStatus.UNAUTHORIZED );
            }
            subject = decodeJWT.getSubject();
            UserDetails userDetails = userDetailsService.loadUserByUsername(subject);
            Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
            scope = authorities
                    .stream().map(auth->auth.getAuthority())
                    .collect(Collectors.joining(" "));
        }
        Map<String, String> idToken = new HashMap<>();
        Instant instant = Instant.now();

        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .subject(subject)
                .issuer("spring_security")
                .expiresAt(instant.plus(withRefreshToken ? 1 : 5, ChronoUnit.MINUTES))
                .issuedAt(instant)
                .claim("scope", scope)
                .build();
        String jwtAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        idToken.put("accessToken", jwtAccessToken);
        if (withRefreshToken){
            JwtClaimsSet jwtClaimsRefreshSet = JwtClaimsSet.builder()
                    .subject(subject)
                    .issuer("spring_security")
                    .expiresAt(instant.plus(5, ChronoUnit.MINUTES))
                    .issuedAt(instant)
                    //.claim("scope", scope) no need for roles here, ust a refresh token , if the access token expires
                    .build();
            String jwtRefreshToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsRefreshSet)).getTokenValue();
            idToken.put("refreshToken", jwtRefreshToken);

        }
        return new ResponseEntity<>(idToken , HttpStatus.OK);
    }



}

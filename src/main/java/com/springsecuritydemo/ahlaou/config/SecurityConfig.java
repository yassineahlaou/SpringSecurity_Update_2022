package com.springsecuritydemo.ahlaou.config;


import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.springsecuritydemo.ahlaou.filters.JwtAuthenticationFilter;
import com.springsecuritydemo.ahlaou.models.Account;
import com.springsecuritydemo.ahlaou.service.AccountService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.Collection;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    //injection via constructor
    private RsakeysConfig rsakeysConfig;

    private PasswordEncoder passwordEncoder;
    private AccountService accountService;
    //constructer
    public SecurityConfig ( RsakeysConfig rsakeysConfig, PasswordEncoder passwordEncoder, AccountService accountService){
        this.rsakeysConfig = rsakeysConfig;
        this.passwordEncoder = passwordEncoder;
        this.accountService = accountService;
    }

    //this method is no more used due to some conflictions
     /*@Bean
     public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
     }*/

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService){
        var authProvider = new DaoAuthenticationProvider();
        authProvider.setPasswordEncoder(passwordEncoder);
        authProvider.setUserDetailsService(userDetailsService);
        return new ProviderManager(authProvider);
    }

    @Bean

    public UserDetailsService userDetailsService (){
        return new UserDetailsService(
               /* User.withUsername("yassine").password(passwordEncoder.encode("1234")).authorities("USER").build(),
               // User.withUsername("lahoucine").password("{noop}1234").authorities("USER").build(),
                User.withUsername("lahoucine").password(passwordEncoder.encode("1234")).authorities("USER").build(),
                User.withUsername("admin").password(passwordEncoder.encode("1234")).authorities("USER", "ADMIN").build()*/
        ) {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                Account newAccount = accountService.loadAccountByUsername(username);
                Collection<GrantedAuthority> authorities = new ArrayList<>();
                newAccount.getAccountRoles().forEach(item->{
                    authorities.add( new SimpleGrantedAuthority(item.getRoleName()));
                });
                return new User(newAccount.getUsername(), newAccount.getPassword(), authorities);
            }
        };
    }

    @Bean
    public SecurityFilterChain filterChain (HttpSecurity httpSecurity) throws Exception{
       // httpSecurity.headers().frameOptions().disable(); //only if we used H2database because it uses frames
       // httpSecurity.formLogin();
        return httpSecurity
                .csrf(csrf-> csrf.disable())//with stateless auth, we should enable csrf because it protcets the app from the CSRF attaques
                .authorizeRequests(auth->auth.antMatchers(
                        "/token/**" ,
                        "/refreshToken/**").permitAll())
                .authorizeRequests(auth-> auth.anyRequest().authenticated())//for basic authentication
                .sessionManagement(sess->sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                //addFilter replace formLogin in stateFull
                .addFilter(new JwtAuthenticationFilter(authenticationManager(userDetailsService()), jwtDecoder(), jwtEncoder()))
                .httpBasic(Customizer.withDefaults()) //use default config
                .build();
    }

    @Bean
    public JwtEncoder jwtEncoder(){
        JWK jwk = new RSAKey.Builder(rsakeysConfig.publicKey()).privateKey(rsakeysConfig.privateKey()).build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(){
        return  NimbusJwtDecoder.withPublicKey(rsakeysConfig.publicKey()).build();
    }
}

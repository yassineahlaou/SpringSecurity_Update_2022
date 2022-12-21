package com.springsecuritydemo.ahlaou.service;


import org.springframework.stereotype.Service;

@Service

public class JwtUserDetailsService /*implements UserDetailsService*/ {

   /* @Autowired
    private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        JwtRequest userExisst = userRepository.findByusername(username);

            return new User(userExisst.getUsername(), userExisst.getPassword(),
                    new ArrayList<>());

    }*/
}

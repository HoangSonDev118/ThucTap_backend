package com.todoapp.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserDetailsService userDetailsService;
    private final CorsConfigurationSource corsConfigurationSource;

    @Bean
    // public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    //     http
    //             // ✅ BẬT CORS
    //             .cors(cors -> cors.configurationSource(corsConfigurationSource))

    //             // ❌ TẮT CSRF
    //             .csrf(AbstractHttpConfigurer::disable)

    //             // ❌ KHÔNG DÙNG SESSION
    //             .sessionManagement(session ->
    //                     session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

    //             // 🔥 QUAN TRỌNG NHẤT
    //             .authorizeHttpRequests(auth -> auth
    //                     // ✅ CHO PHÉP OPTIONS (CORS PREFLIGHT)
    //                     .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

    //                     // ✅ PUBLIC API
    //                     .requestMatchers("/api/auth/**").permitAll()
    //                     .requestMatchers("/api/public/**").permitAll()
    //                     .requestMatchers("/api/users/search").permitAll()

    //                     // 🔒 CÒN LẠI CẦN JWT
    //                     .anyRequest().authenticated()
    //             )

    //             .authenticationProvider(authenticationProvider())

    //             // ✅ JWT FILTER
    //             .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

    //     return http.build();
    // }
    @Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.disable())
        .cors(cors -> {})
        .authorizeHttpRequests(auth -> auth
            .anyRequest().permitAll()
        );
    return http.build();
}


    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config
    ) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

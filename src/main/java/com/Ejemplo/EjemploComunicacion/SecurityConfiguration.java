package com.Ejemplo.EjemploComunicacion;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
            @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            // @formatter:off
            http
                    .authorizeHttpRequests((authorize) -> authorize

                    .requestMatchers("/Camas").authenticated()
                    .requestMatchers("/Aseo").authenticated()
                    .requestMatchers("/Comida").authenticated()
                    .requestMatchers("/Juguetes").authenticated()
                    .requestMatchers("/Ropa").authenticated()
                    .anyRequest().authenticated()
                    )
                    .httpBasic(withDefaults())
                    .formLogin(withDefaults());
            // @formatter:on
            return http.build();
        }
        @Bean

        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }

        @Bean
        public InMemoryUserDetailsManager userDetailsService() {
            PasswordEncoder passwordEncoder = passwordEncoder();
            UserDetails user = User.builder()
                    .username("user")
                    .password(passwordEncoder.encode("Hiañ00F1153.desic°00B0hier"))
                    .roles("USER")
                    .build();
            return new InMemoryUserDetailsManager(user);

        }
}

package amera.demo_jwt.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import amera.demo_jwt.Jwt.JwtAuthenticationFilter;

// import static org.springframework.security.config.Customizer.withDefaults;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authProvider;
    /**
     *  @Bean.- Se utiliza para luego ser expresado en objeto
     *  return http .- Quiere decir  pasara por una serie de filtros primero
     *  1.- rutas privadas  y protegidas con el requestMatchers con la ruta auth/ sea publico
     *  y cualquier otro  anyRequest se auto-identifique
     *  2.-formLogin es el formulario por defecto se utilizo e importo el withDefaults()
     *  3.- CSRF ayuda a dar una auntentificación token válido
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        return http
            .csrf(csrf ->
                csrf
                .disable())
            .authorizeHttpRequests(authRequest ->
                authRequest
                .requestMatchers("/auth/**").permitAll()
                .anyRequest().authenticated()
                )
            .sessionManagement(sessionManager->
                sessionManager
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authenticationProvider(authProvider)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class) // este es un autenticación basada en JWT 
            // .formLogin(withDefaults()) // Por defecto era el login de spring security
            .build();

    }
}

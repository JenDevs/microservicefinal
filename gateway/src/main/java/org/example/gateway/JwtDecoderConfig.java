package org.example.gateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

@Configuration
public class JwtDecoderConfig {

    @Bean
    @Profile("docker")
    public ReactiveJwtDecoder jwtDecoderDocker() {
        return NimbusReactiveJwtDecoder.withJwkSetUri("http://authservice:9000/oauth2/jwks").build();
    }
}

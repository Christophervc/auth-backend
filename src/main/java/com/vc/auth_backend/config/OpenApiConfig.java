package com.vc.auth_backend.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.models.OpenAPI;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "Auth Backend API",
                version = "v1",
                description = "Documentacion backend: autenticacion, usuarios, manejo de sesiones"
        )
)
@SecurityScheme(
        name = OpenApiConfig.BEARER_SCHEME,
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT",
        description = "Autenticacion con access token JWT enviado en el header Authorization: Bearer {token}."
)
@SecurityScheme(
        name = OpenApiConfig.COOKIE_SCHEME,
        type = SecuritySchemeType.APIKEY,
        in = SecuritySchemeIn.COOKIE,
        paramName = "access_token",
        description = "Autenticacion con JWT almacenado en la cookie http-only access_token."
)
public class OpenApiConfig {
    public static final String BEARER_SCHEME = "bearerAuth";
    public static final String COOKIE_SCHEME = "cookieAuth";

    @Bean
    public OpenAPI authOpenApi() {
        return new OpenAPI()
                .info(new io.swagger.v3.oas.models.info.Info()
                        .title("Auth backend API")
                        .version("v1")
                        .description("API REST para administrar autenticacion, usuarios, media."));
    }
}

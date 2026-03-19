package com.vlz.laborexchange_apigetaway.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("LaborExchange API Gateway")
                        .version("1.0.0")
                        .description("""
                                Single entry point for all LaborExchange microservices.

                                **Authentication:** Include a JWT token in the `Authorization` header for all protected endpoints:
                                ```
                                Authorization: Bearer <token>
                                ```
                                Obtain a token via `POST /api/auth/login` or `POST /api/auth/register`.

                                **Public endpoints (no JWT required):**
                                - `POST /api/auth/register`
                                - `POST /api/auth/login`
                                - `POST /api/vacancies/reindex`
                                - `POST /api/resumes/reindex`

                                **Rate limiting (per IP, sliding window):**
                                - `/api/auth/*` — 20 requests / 60 seconds
                                - All other paths — 100 requests / 60 seconds

                                **Routing table:**

                                | Path prefix | Upstream service | Port |
                                |---|---|---|
                                | `/api/auth/**` | Auth Service | 8081 |
                                | `/api/users/**` | User Service | 8082 |
                                | `/api/roles/**` | User Service | 8082 |
                                | `/api/vacancies/**` | Vacancy Service | 8083 |
                                | `/api/companies/**` | Vacancy Service | 8083 |
                                | `/api/resumes/**` | Resume Service | 8084 |
                                | `/api/educations/**` | Resume Service | 8084 |
                                | `/api/applications/**` | Application Service | 8085 |
                                | `/api/skills/**` | Skill Service | 8086 |
                                | `/api/search/**` | Search Service | 8087 |

                                **Per-service Swagger UI docs** are aggregated here and available in the dropdown above.
                                """)
                        .contact(new Contact().name("LaborExchange Team"))
                        .license(new License().name("MIT")))
                .servers(List.of(
                        new Server().url("http://localhost:8080").description("API Gateway")));
    }
}

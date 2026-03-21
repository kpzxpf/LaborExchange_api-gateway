# API Gateway

![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.3.4-brightgreen?logo=springboot)
![Java](https://img.shields.io/badge/Java-17-orange?logo=openjdk)
![Port](https://img.shields.io/badge/port-8080-blue)
![WebFlux](https://img.shields.io/badge/WebFlux-reactive-6DB33F?logo=spring)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

Reactive API Gateway — single entry point for all microservices. Handles JWT validation, request routing, header injection, rate limiting, and CORS.

## Table of Contents

- [Overview](#overview)
- [Routing](#routing)
- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [CORS](#cors)
- [Swagger Aggregation](#swagger-aggregation)
- [Configuration](#configuration)
- [Running Locally](#running-locally)

## Overview

| Property | Value |
|---|---|
| Port | **8080** |
| Framework | Spring Cloud Gateway (WebFlux) |
| Auth | JWT (HS256), validated locally |
| Swagger UI | `http://localhost:8080/swagger-ui.html` |
| OpenAPI JSON | `http://localhost:8080/v3/api-docs` |
| Prometheus | `http://localhost:8080/actuator/prometheus` |

## Routing

| Path prefix | Upstream | Port |
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

## Authentication

For protected endpoints, include the JWT in the `Authorization` header:

```
Authorization: Bearer <token>
```

Obtain a token via `POST /api/auth/login` or `POST /api/auth/register`.

The Gateway validates the JWT signature and expiry, then injects the following headers into the upstream request:

| Header | Value |
|---|---|
| `X-User-Id` | Numeric user ID from `userId` claim |
| `X-User-Role` | User role from `role` claim |
| `X-User-Email` | Email from `sub` claim |

**Public endpoints** (no JWT required):

| Path | Method |
|---|---|
| `/api/auth/register` | `POST` |
| `/api/auth/login` | `POST` |
| `/api/auth/validate` | `GET` |
| `/api/vacancies/reindex` | `POST` |
| `/api/resumes/reindex` | `POST` |
| `/api/search/**` | `GET` |

## Rate Limiting

Rate limiting is applied per-IP using a **Redis-backed sliding window**:

| Route | Limit |
|---|---|
| `/api/auth/*` | 20 requests / 60 s |
| All other paths | 100 requests / 60 s |

Returns `429 Too Many Requests` when the limit is exceeded.

## CORS

CORS is configured via `app.cors.allowed-origins` in `application.yaml`. Allowed methods: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`.

## Swagger Aggregation

The Gateway aggregates OpenAPI specs from all downstream services. Access the unified Swagger UI at:

```
http://localhost:8080/swagger-ui.html
```

Use the **service dropdown** in the top-right corner to switch between service APIs.

## Configuration

| Property | Default | Description |
|---|---|---|
| `server.port` | `8080` | Gateway HTTP port |
| `spring.jwt.secret` | env var | JWT signing key (shared with Auth Service) |
| `app.cors.allowed-origins` | `http://localhost:3000` | Frontend origin |
| `spring.data.redis.host` | `localhost` | Redis host (for rate limiting) |

## Running Locally

All downstream services should be running before starting the Gateway:

```bash
./gradlew bootRun
```

Requires Redis for rate limiting.

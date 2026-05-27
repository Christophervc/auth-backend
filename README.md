# Auth backend

Backend REST para autenticacion con JWT, manejo de sesiones con refresh tokens, carga de imagenes.

## Tabla de contenido

- [Resumen](#resumen)
- [Stack tecnologico](#stack-tecnologico)
- [Capacidades principales](#capacidades-principales)
- [Arquitectura y modulos](#arquitectura-y-modulos)
- [Autenticacion y autorizacion](#autenticacion-y-autorizacion)
- [Rate limiting](#rate-limiting)
- [Endpoints](#endpoints)
- [Decisiones tecnicas](#decisiones-tecnicas)
- [Configuracion local](#configuracion-local)
- [Ejecucion](#ejecucion)
- [OpenAPI y Swagger](#openapi-y-swagger)
- [Formato de errores](#formato-de-errores)

## Resumen

El proyecto esta construido con Spring Boot y expone una API versionada bajo `/api/v1`. El dominio principal cubre:

- autenticacion con JWT y refresh tokens persistidos
- perfiles de usuario y control de roles
- carga y limpieza de avatars en Cloudinary


La API usa cookies `http-only` para navegadores, pero mantiene compatibilidad con `Authorization: Bearer <token>` para clientes moviles, integraciones o testing manual.

## Stack tecnologico

### Base

- Java 25
- Spring Boot 4.0.6
- Gradle Wrapper (`gradlew`, `gradlew.cmd`)

### Web y API

- Spring Web
- Spring Validation
- Spring Problem Details
- Springdoc OpenAPI / Swagger UI

### Seguridad

- Spring Security
- JWT con `jjwt`
- cookies `http-only` para access token y refresh token
- autorizacion por roles con `@PreAuthorize`

### Persistencia

- Spring Data JPA
- PostgreSQL

### Integraciones externas

- Cloudinary para almacenamiento de imagenes

### Calidad y soporte

- MapStruct para mapeo DTO <-> entidad
- Lombok
- Bucket4j para rate limiting
- Caffeine para cache de buckets
- H2 para pruebas
- Virtual Threads habilitados

## Capacidades principales

- login, registro, refresh, logout y logout global
- maximo de 4 sesiones activas por usuario
- access token y refresh token en cookies seguras para frontend web
- compatibilidad adicional con bearer token en header
- control de acceso por roles `USER`, `ADMIN`
- carga de imagenes de perfil (avatar) validando tipo y tamano
- respuestas de error consistentes con `ProblemDetail`
- rate limiting segmentado por tipo de endpoint

## Arquitectura y modulos

La estructura sigue una organizacion por modulos funcionales:

- `modules/auth`: login, registro, refresh tokens, cookies, JWT
- `modules/user`: perfiles, roles, estado del usuario, estadisticas
- `modules/media`: carga y borrado de imagenes
- `config`: seguridad, OpenAPI, rate limiting
- `shared`: DTOs comunes y manejo global de excepciones

## Autenticacion y autorizacion

### Mecanismo de autenticacion

El backend soporta dos canales de autenticacion:

1. Cookie `http-only` `access_token`
2. Header `Authorization: Bearer <jwt>`

El filtro `JwtAuthenticationFilter` intenta primero leer el header `Authorization` y, si no existe, usa la cookie `access_token`. Eso permite que:

- el frontend web trabaje con cookies protegidas contra acceso desde JavaScript
- clientes no browser sigan usando bearer tokens sin cambios

### Refresh token

- el refresh token tambien se guarda en cookie `http-only`
- los refresh tokens se persisten en base de datos
- al refrescar sesion, el refresh token actual se revoca y se emite uno nuevo
- `logout` revoca la sesion actual
- `logout-all` revoca todas las sesiones del usuario

### Roles

- `USER`: uso normal de la plataforma
- `ADMIN`: control completo, incluyendo cambios de rol y borrado administrativo

## Rate limiting

El rate limit se aplica a nivel de filtro sobre `/api/v1/**`.

Politicas actuales:

- endpoints generales: `90` requests por minuto
- autenticacion (`/auth/login`, `/auth/register`): `10` requests por minuto
- IA (`/ai/**`): `3` requests por dia

Identificacion del cliente:

- si el usuario esta autenticado, se usa su `userId`
- si no lo esta, se usa `request.getRemoteAddr()`

Implementacion:

- Bucket4j para el control de tokens
- Caffeine para cachear buckets por cliente

## Endpoints

### Auth

| Metodo | Ruta | Acceso | Descripcion |
| --- | --- | --- | --- |
| `POST` | `/api/v1/auth/login` | Publico | autentica credenciales y escribe cookies de sesion |
| `POST` | `/api/v1/auth/register` | Publico | registra un usuario y abre sesion |
| `POST` | `/api/v1/auth/refresh` | Publico con cookie de refresh | rota tokens usando `refresh_token` |
| `POST` | `/api/v1/auth/logout` | Publico con cookie de refresh opcional | limpia cookies y revoca la sesion actual si existe |
| `POST` | `/api/v1/auth/logout-all` | Autenticado | revoca todas las sesiones del usuario |

### Users

| Metodo | Ruta | Acceso | Descripcion |
| --- | --- | --- | --- |
| `GET` | `/api/v1/users/me` | Autenticado | obtiene el perfil del usuario actual |
| `GET` | `/api/v1/users` | `ADMIN` | lista usuarios paginados |
| `PATCH` | `/api/v1/users/{id}/status` | `ADMIN` | activa o desactiva un usuario |
| `PATCH` | `/api/v1/users/{id}/role` | `ADMIN` | cambia el rol de un usuario |
| `GET` | `/api/v1/users/{id}/stats` | `ADMIN`| obtiene estadisticas agregadas del usuario |
| `PUT` | `/api/v1/users/me` | Autenticado | actualiza perfil propio |
| `GET` | `/api/v1/users/{id}/public` | Publico | obtiene perfil publico |
| `PATCH` | `/api/v1/users/me/change-password` | Autenticado | cambia la contrasena propia |
| `DELETE` | `/api/v1/users/me` | Autenticado | desactiva la cuenta propia |

### Media

| Metodo | Ruta | Acceso | Descripcion |
| --- | --- | --- | --- |
| `POST` | `/api/v1/media/upload` | Autenticado | sube una imagen a Cloudinary |
| `DELETE` | `/api/v1/media/{postId}/images/{imageId}` | Autenticado | elimina una imagen de un post |

Restricciones de upload:

- tipos permitidos: `image/jpeg`, `image/png`, `image/webp`, `image/gif`
- tamano maximo: `5MB`
- carpetas permitidas: `avatars`, `covers`

## Decisiones tecnicas

### 2. Limite de 4 sesiones activas por usuario

La regla de negocio se implementa en `RefreshTokenService` con `MAX_ACTIVE_SESSIONS = 4`.

Motivos:

- controla abuso de cuentas compartidas
- acota la cantidad de refresh tokens activos que se deben mantener
- reduce superficie de riesgo si un usuario deja sesiones abiertas en varios dispositivos
- sigue siendo un limite razonable para uso real: desktop, laptop, movil y una sesion adicional

Detalle importante:

- el control se hace sobre refresh tokens activos, no sobre access tokens
- antes de contar sesiones activas, el servicio limpia refresh tokens expirados del usuario
- si se alcanza el maximo, se responde con `409 Conflict`

### 3. Cookies `http-only` en lugar de exponer tokens al frontend

El sistema prioriza cookies `http-only` para web y conserva bearer token como compatibilidad.

Motivos:

- un token guardado en `localStorage` o accesible desde JavaScript queda mas expuesto ante XSS
- una cookie `http-only` no puede ser leida desde el codigo del navegador
- `SameSite` y `Secure` permiten endurecer la politica segun ambiente
- el filtro JWT mantiene compatibilidad con clientes que no usan cookies

Resultado:

- frontend browser: flujo principal con cookies
- mobile/API clients: flujo compatible con bearer token

### 5. `RateLimitFilter#doFilterInternal` en lugar de `HandlerInterceptor`

En este proyecto el rate limiting se implementa como filtro (`OncePerRequestFilter`) y no como `WebMvc Interceptor`.

Motivos tecnicos:

- el filtro actua mas temprano en la cadena de request, antes del despacho MVC y antes de parte del trabajo del controlador
- permite cortar la peticion con `429` sin entrar a la resolucion del handler
- convive mejor con el endpoint SSE `/api/v1/ai/improve/stream`, donde un interceptor puede ser mas propenso a comportamientos incomodos alrededor del ciclo async/streaming
- el proyecto ya resuelve autenticacion por filtros; aplicar rate limiting en la misma capa reduce diferencias de comportamiento entre rutas normales y rutas streaming
- el filtro puede distinguir rutas de IA, auth y generales con costo muy bajo y sin depender del binding MVC

En particular para SSE:

- el endpoint de IA responde con `text/event-stream`
- una vez abierto el stream, conviene que los rechazos ocurran antes de entrar a la logica del handler
- el filtro evita problemas de orden entre preHandle/postHandle/afterCompletion y el lifecycle async de una respuesta que puede permanecer abierta durante mas tiempo

### 7. Refresh token persistido y revocable

El refresh token no es puramente stateless. Se persiste y tiene bandera `revoked`.

Motivos:

- habilita logout real por sesion
- habilita logout global
- habilita limite de sesiones concurrentes
- permite invalidar sesiones aun cuando el JWT de refresh no haya expirado

### 8. Rate limiting por categoria de trafico

No todas las rutas tienen el mismo costo ni el mismo perfil de abuso:

- `login/register` necesitan proteccion adicional ante brute force
- IA cuesta mas dinero y tiempo que un endpoint CRUD normal
- endpoints generales requieren una politica mas permisiva

Por eso se usan buckets separados:

- `AUTH`
- `AI`
- `GEN`

### 9. OpenAPI alineado con seguridad real

La documentacion OpenAPI modela los dos mecanismos validos de autenticacion:

- `bearerAuth`
- `cookieAuth`

Esto evita documentacion incompleta donde Swagger solo muestre bearer token cuando el frontend real usa cookies `http-only`.

## Configuracion local

### Requisitos

- Java 25
- PostgreSQL 17
- Gradle Wrapper

### Variables y propiedades relevantes

El proyecto usa `application.properties`, `application-dev.properties` y `.env`.

Configurar al menos:

- `spring.datasource.url`
- `spring.datasource.username`
- `spring.datasource.password`
- `jwt.secret`
- `jwt.time.expiration`
- `jwt.time.refresh-expiration`
- `cloudinary.cloud-name`
- `cloudinary.api-key`
- `cloudinary.api-secret`

Propiedades destacadas:

- `spring.jpa.open-in-view=false`
- `spring.threads.virtual.enabled=true`
- `spring.mvc.problemdetails.enabled=true`
- `app.cookie.secure`
- `app.cookie.same-site`

### Nota operativa

Las credenciales y secretos deben tratarse como configuracion sensible del entorno. Para ambientes reales, conviene moverlos a variables de entorno o un secret manager y no mantener valores reales en archivos versionados.

## Ejecucion

### 1. Levantar PostgreSQL con Docker Compose

```powershell
docker compose up -d
```

### 2. Ejecutar la aplicacion

```powershell
.\mvnw.cmd spring-boot:run
```

### 3. Compilar

```powershell
.\gradlew.cmd clean compile
```

### 4. Ejecutar tests

```powershell
.\gradlew.cmd test
```

## OpenAPI y Swagger

Documentacion disponible una vez levantada la aplicacion:

- Swagger UI: `http://localhost:8080/swagger-ui.html`
- OpenAPI JSON: `http://localhost:8080/v3/api-docs`

La configuracion OpenAPI documenta:

- tags por controlador
- summary y description por endpoint
- `ParameterObject` para filtros
- seguridad por cookie y bearer token en endpoints protegidos

## Formato de errores

La API usa `ProblemDetail` y `application/problem+json` para respuestas de error.

Casos cubiertos:

- `400 Bad Request` para validaciones o argumentos invalidos
- `401 Unauthorized` para credenciales invalidas o tokens invalidos
- `403 Forbidden` para acceso denegado
- `404 Not Found` para recursos inexistentes o drafts no visibles
- `409 Conflict` para conflictos de negocio, incluyendo limite de sesiones
- `429 Too Many Requests` para rate limiting
- `503 Service Unavailable` para fallas de servicios externos
- `500 Internal Server Error` con `traceId` para errores no controlados

## Resumen de la propuesta tecnica

Este backend privilegia decisiones conservadoras en seguridad y operacion:

- cookies `http-only` para reducir exposicion de tokens
- refresh tokens persistidos para logout real y control de sesiones
- rate limiting estratificado por costo y riesgo

# Auth Backend

API REST de autenticación y gestión de usuarios construida con Spring Boot. Expone sus recursos bajo `/api/v1` y prioriza sesiones seguras con JWT en cookies `HttpOnly`, tokens de refresco revocables y controles de abuso.

## Capacidades

- Registro local con verificación de correo mediante código de un solo uso.
- Inicio de sesión local y con Google OAuth2.
- JWT de acceso y refresh tokens persistidos, rotativos y revocables.
- Gestión de sesiones por dispositivo: consulta, cierre remoto y cierre global; máximo de cuatro sesiones activas por usuario.
- Autenticación de dos factores (TOTP), QR de configuración, códigos de respaldo y detección de reutilización de códigos.
- Recuperación de contraseña por OTP; al restablecerla se revocan todas las sesiones.
- Perfiles de usuario, administración por rol y avatar almacenado en Cloudinary.
- Validación y sanitización de avatares: firmas de archivo, decodificación, límite de dimensiones y recodificación de la imagen.
- Rate limiting por categoría de operación e identificación por usuario autenticado o IP.
- Errores uniformes con `ProblemDetail` y documentación OpenAPI/Swagger.

## Stack

- Java 25 y Spring Boot 4
- Spring Security, OAuth2 Client y JWT (`jjwt`)
- PostgreSQL con Spring Data JPA
- Redis para códigos temporales y estado de pre-autenticación
- Cloudinary para avatares
- Resend para envío de correos
- Bucket4j y Caffeine para rate limiting
- TOTP, ZXing y TwelveMonkeys ImageIO para 2FA y procesamiento de imágenes
- Gradle Wrapper y Docker Compose

## Autenticación y seguridad

La API acepta autenticación mediante:

1. Cookie `access_token` con `HttpOnly` para aplicaciones web.
2. Encabezado `Authorization: Bearer <jwt>` para clientes no basados en navegador.

El filtro JWT prioriza el encabezado Bearer y usa la cookie si no está presente. Los tokens de acceso expiran a corto plazo; el refresh token se guarda en una cookie `HttpOnly`, se persiste en la base de datos y se rota al refrescar la sesión.

Las cuentas locales deben verificar su correo antes de iniciar sesión. Las cuentas creadas desde Google se consideran verificadas. OAuth2 usa el flujo estándar de Spring Security; el inicio se realiza en `/oauth2/authorization/google` y, tras completar el flujo, se establecen las cookies de sesión antes de redirigir al frontend configurado.

### Roles

- `USER`: operaciones propias de la cuenta.
- `ADMIN`: administración de roles.

Las operaciones de listado y cambio de estado están protegidas para `ADMIN` a nivel de controlador; actualmente el enum de roles del proyecto define `USER` y `ADMIN`.

### Sesiones y 2FA

- Se permiten hasta **4 sesiones activas** por usuario.
- Cada sesión registra dispositivo, sistema operativo, tipo de dispositivo, IP y última actividad.
- El usuario puede revocar una sesión individual o todas sus sesiones.
- 2FA usa códigos TOTP de seis dígitos y códigos de respaldo de un solo uso.
- Durante el login con 2FA se utiliza una cookie temporal `pre_auth_token`; solo después de validar el código se emiten las cookies finales.
- Desactivar 2FA y restablecer la contraseña revoca las sesiones activas.

## Rate limiting

Se aplica a `/api/v1/**`. Para usuarios autenticados se usa el ID de usuario como clave; para solicitudes anónimas se usa la IP (se valida el primer valor de `X-Forwarded-For` cuando es válido).

| Categoría | Rutas | Límite |
| --- | --- | --- |
| General | resto de la API | 90 solicitudes/minuto |
| Login | `/auth/login` | 10 solicitudes/minuto |
| Registro | `/auth/register` | 5 solicitudes/10 minutos |
| Recuperación OTP | `/auth/forgot-password`, `/verify-otp`, `/reset-password` | 3 solicitudes/hora |
| Verificación de correo | `/auth/verify-email`, `/resend-verification` | 4 solicitudes/hora |
| 2FA | `/auth/2fa/**` | 5 solicitudes/15 minutos |

## Endpoints

Las rutas siguientes tienen el prefijo `/api/v1`.

### Autenticación

| Método | Ruta | Acceso | Descripción |
| --- | --- | --- | --- |
| `POST` | `/auth/register` | Público | Crea una cuenta local pendiente de verificación y envía el código por correo. La respuesta no revela si el correo ya existe. |
| `POST` | `/auth/verify-email` | Público | Verifica el código de correo; la operación es idempotente. |
| `POST` | `/auth/resend-verification` | Público | Reenvía el código sin revelar si la cuenta existe o ya está verificada. |
| `POST` | `/auth/login` | Público | Inicia sesión; si 2FA está activo, inicia la preautenticación. |
| `POST` | `/auth/refresh` | Cookie de refresh | Rota el refresh token y actualiza las cookies de sesión. |
| `POST` | `/auth/logout` | Público con cookie opcional | Revoca la sesión actual cuando existe y limpia las cookies. |
| `POST` | `/auth/logout-all` | Autenticado | Revoca todas las sesiones del usuario. |
| `GET` | `/auth/sessions` | Autenticado | Lista las sesiones activas, incluida la marca de sesión actual. |
| `DELETE` | `/auth/sessions/{sessionId}` | Autenticado | Revoca una sesión propia por ID. |
| `POST` | `/auth/forgot-password` | Público | Envía un OTP de recuperación sin revelar si el correo está registrado. |
| `POST` | `/auth/verify-otp` | Público | Valida un OTP sin consumirlo. |
| `POST` | `/auth/reset-password` | Público | Cambia la contraseña, consume el OTP y revoca todas las sesiones. |

### Autenticación de dos factores

| Método | Ruta | Acceso | Descripción |
| --- | --- | --- | --- |
| `POST` | `/auth/2fa/setup` | Autenticado | Genera el secreto y el QR para configurar una aplicación autenticadora. |
| `POST` | `/auth/2fa/confirm-setup` | Autenticado | Confirma el primer código TOTP, activa 2FA y devuelve los códigos de respaldo una sola vez. |
| `POST` | `/auth/2fa/verify` | Público con cookie de preautenticación | Completa el login con un código TOTP o de respaldo. |
| `POST` | `/auth/2fa/disable` | Autenticado | Desactiva 2FA tras validar un código TOTP. |

### Usuarios

| Método | Ruta | Acceso | Descripción |
| --- | --- | --- | --- |
| `GET` | `/users/me` | Autenticado | Obtiene el perfil propio. |
| `PUT` | `/users/me` | Autenticado | Actualiza los datos editables del perfil propio. |
| `PATCH` | `/users/me/change-password` | Autenticado | Cambia la contraseña propia. |
| `DELETE` | `/users/me` | Autenticado | Desactiva la cuenta propia. |
| `PUT` | `/users/me/avatar` | Autenticado | Sube o reemplaza el avatar (`multipart/form-data`, campo `file`). |
| `DELETE` | `/users/me/avatar` | Autenticado | Elimina el avatar. |
| `GET` | `/users/{id}/public` | Autenticado | Obtiene el perfil público de un usuario. |
| `GET` | `/users` | `ADMIN`| Lista usuarios paginados. |
| `PATCH` | `/users/{id}/status` | `ADMIN` | Activa o desactiva un usuario. |
| `PATCH` | `/users/{id}/role` | `ADMIN` | Cambia el rol de un usuario. |

### Avatar

El avatar admite JPEG, PNG, WEBP y GIF, con un límite de **2 MB** y dimensiones máximas de **2000 × 2000 px**. La imagen se vuelve a codificar antes de enviarse a Cloudinary, lo que elimina metadatos y reduce riesgos de archivos polyglot. Al reemplazar un avatar propio se elimina el archivo anterior; para avatares de Google solo se elimina la referencia local.

## Configuración local

### Requisitos

- Java 25
- Docker y Docker Compose (PostgreSQL 17 y Redis 7)

### Variables de entorno

No versionar credenciales reales. Crea un archivo `.env` para Docker y proporciona los secretos por variables de entorno o por un perfil local no versionado.

```dotenv
POSTGRES_USER=auth_user
POSTGRES_PASSWORD=una_contrasena_segura
POSTGRES_DB=auth_db

REDIS_HOST=localhost
REDIS_PORT=6379

CLOUDINARY_CLOUD_NAME=...
CLOUDINARY_API_KEY=...
CLOUDINARY_API_SECRET=...

EMAIL_FROM=...
RESEND_API_KEY=...
OTP_EXPIRATION_MINUTES=10
ENCRYPTION_SECRET_KEY=<clave_AES_base64_de_32_bytes>

OAUTH2_REDIRECT_SUCCESS=http://localhost:3000/auth/callback
OAUTH2_REDIRECT_FAILURE=http://localhost:3000/login
```

Además de las propiedades de base de datos y JWT, para Google OAuth2 se requieren `spring.security.oauth2.client.registration.google.client-id`, `client-secret`, `scope=openid,email,profile` y una URL de callback que coincida con la registrada en Google Cloud Console: `http://localhost:8080/login/oauth2/code/google` en desarrollo.

Propiedades relevantes:

- `jwt.secret`, `jwt.time.expiration`, `jwt.time.refresh-expiration`
- `app.cookie.secure`, `app.cookie.same-site`
- `app.otp.expiration-minutes`, `app.email-verification.expiration-minutes`
- `app.2fa.pre-auth-expiration-minutes`, `app.2fa.issuer`, `app.2fa.digits`, `app.2fa.period`
- `app.encryption.secret-key` para cifrar secretos 2FA y códigos de respaldo en reposo

En producción, habilita cookies seguras, configura CORS con el dominio real del frontend, usa Redis con contraseña/TLS y almacena todos los secretos en un gestor de secretos.

## Ejecución

```powershell
# Levanta PostgreSQL y Redis
docker compose up -d

# Ejecuta la aplicación
.\gradlew.bat bootRun

# Compila y ejecuta las pruebas
.\gradlew.bat test
```

Servicios locales de Docker:

- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`
- Redis Commander: `http://localhost:8081`

## OpenAPI y errores

Con la aplicación en ejecución:

- Swagger UI: `http://localhost:8080/swagger-ui.html`
- OpenAPI JSON: `http://localhost:8080/v3/api-docs`

Los errores usan `application/problem+json` mediante `ProblemDetail`. Entre los estados habituales están `400` para validaciones, `401` para autenticación faltante o inválida, `403` para autorización, `404` para recursos inexistentes, `409` para conflictos como el límite de sesiones, `429` para rate limiting y `503` para fallos de servicios externos.

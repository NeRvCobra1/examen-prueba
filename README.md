# ExamenPrueba

Blazor Web App en .NET 10 con servidor ASP.NET Core, cliente WebAssembly, Identity, EF Core y SQLite. E1 incorpora roles, permisos, autorización y límite de login; E2 agrega el CRUD de usuarios; E3 agrega el CRUD de roles y la gestión Usuario–Rol. El alcance de las entregas y las reglas de trabajo están en [AGENTS.md](AGENTS.md).

## Requisitos y arranque local

- SDK .NET 10 y Python 3 para la prueba automatizada opcional.
- Certificado de desarrollo HTTPS instalado. Verificarlo con `dotnet dev-certs https --check --verbose`; el proyecto no modifica certificados del sistema.

Desde la raíz del repositorio, en la terminal de VS Code:

```powershell
dotnet restore ExamenPrueba.sln
dotnet tool restore
dotnet build ExamenPrueba.sln
dotnet run --project ExamenPrueba --launch-profile https
```

Abrir `https://localhost:7205`. El perfil también escucha en `http://localhost:5080` y redirige a HTTPS. Si los puertos están ocupados, consultar `ExamenPrueba/Properties/launchSettings.json`. El certificado de desarrollo debe ser confiable en el navegador usado para la prueba.

## Base de datos y migraciones

`DefaultConnection` usa `ExamenPrueba/Data/app.db` cuando la aplicación se ejecuta desde el proyecto servidor. La aplicación aplica las migraciones al iniciar. También se pueden aplicar manualmente desde `ExamenPrueba` con `dotnet dotnet-ef database update` después de `dotnet tool restore`.

Las migraciones son `00000000000000_CreateIdentitySchema` y `20261106232734_AddRoleBasedPermissions`. La segunda solo agrega `Permissions`, `RolePermissions`, sus claves, relaciones e índices. Conserva todas las tablas originales de Identity, incluida `AspNetUserPasskeys`. En una base existente, crear primero un respaldo consistente de SQLite y comprobar las migraciones pendientes. La base y sus respaldos `*.db` están excluidos de Git.

## Cuentas y prueba manual de E1

1. En `https://localhost:7205/Account/Register`, registrar una cuenta. El servidor asigna exclusivamente `User`, sin aceptar un rol enviado desde el formulario.
2. Abrir el vínculo de confirmación que muestra la página `RegisterConfirmation` en Development. La plantilla usa un emisor de correo simulado; no envía correo real.
3. Iniciar sesión en `/Account/Login`. Abrir `/dashboard`: debe mostrar correo, rol `User`, ausencia de permisos administrativos y el mensaje de acceso denegado para el resumen. La página hace solicitudes HTTP del navegador a `/api/auth/me`, `/api/security/capabilities` y `/api/admin/overview`; se pueden observar en la pestaña Network de las herramientas del navegador.
4. Abrir `/Account/Manage` para verificar una página protegida. Cerrar sesión desde el menú de cuenta. Sin sesión, `/dashboard` conduce a login y las tres APIs devuelven HTTP 401.

Para crear **una cuenta Admin de prueba exclusivamente en Development**, configurar User Secrets fuera del repositorio desde la raíz (sustituir los marcadores por un correo y una contraseña propios, sin guardarlos en archivos versionados):

```powershell
dotnet user-secrets set "AdminBootstrap:Enabled" "true" --project ExamenPrueba
dotnet user-secrets set "AdminBootstrap:Email" "<correo-admin-de-prueba>" --project ExamenPrueba
dotnet user-secrets set "AdminBootstrap:Password" "<contraseña-de-prueba>" --project ExamenPrueba
dotnet run --project ExamenPrueba --launch-profile https
```

El bootstrap se ejecuta solo si `AdminBootstrap:Enabled` es `true` y el entorno es Development. Crea una cuenta nueva confirmada con rol `Admin`; si el correo ya pertenece a una cuenta sin ese rol, detiene el arranque y no la eleva. Es idempotente. Después de crearla, detener el servidor y desactivar el bootstrap:

```powershell
dotnet user-secrets set "AdminBootstrap:Enabled" "false" --project ExamenPrueba
```

Reiniciar y acceder con esa cuenta. `/dashboard` debe mostrar los doce permisos y el resumen administrativo. El servidor consulta SQLite para resolver cada permiso efectivo; el navegador no decide el acceso. El bootstrap es para desarrollo local. E2 administra usuarios y E3 administra roles y asignaciones Usuario–Rol. La administración de permisos corresponde a E4 y no está implementada.

## APIs y límite de login

| Ruta | Acceso | Resultado esperado |
| --- | --- | --- |
| `GET /api/auth/me` | Usuario autenticado | Id, correo y roles; anónimo: 401. |
| `GET /api/security/capabilities` | Usuario autenticado | Códigos de permisos efectivos; anónimo: 401. |
| `GET /api/admin/overview` | Permiso `users.read` | Resumen sin datos sensibles; anónimo: 401; sin permiso: 403. |

La política de rate limiting protege el **POST real `/Account/Login`** de Identity: ventana fija de 60 segundos, cinco solicitudes por IP, sin cola y respuesta 429 con `Retry-After` al excederla. `GET /Account/Login` y la navegación normal quedan fuera del límite. Los valores se configuran en `RateLimiting:Login` dentro de `ExamenPrueba/appsettings.json` o mediante configuración del entorno. Se usa la IP de la conexión, sin confiar en cabeceras IP enviadas por el cliente. Se conserva antiforgery y la configuración segura de cookies de la plantilla.

## CRUD de usuarios (E2)

| Método y ruta | Permiso | Respuesta principal |
| --- | --- | --- |
| `GET /api/users?page=1&pageSize=10&search=` | `users.read` | 200: lista paginada, total y roles de consulta. Máximo 50 por página. |
| `GET /api/users/{id}` | `users.read` | 200: detalle seguro; 404 si falta. |
| `POST /api/users` | `users.create` | 201: usuario nuevo con rol `User`, correo sin confirmar; 400/409 para datos inválidos o duplicados. |
| `PUT /api/users/{id}` | `users.update` | 200: correo actualizado; requiere reconfirmación si cambió; 400/404/409 según el caso. |
| `DELETE /api/users/{id}` | `users.delete` | 204: eliminación física; 404 si falta y 409 para cuenta propia o último Admin. |

Las respuestas solo exponen Id, correo, confirmación y roles. POST acepta `email`, `password` y `confirmPassword`; PUT acepta únicamente `email`. Los campos adicionales se rechazan. Identity valida contraseñas y unicidad de correo. El alta y la edición generan un vínculo de confirmación a partir de `Application:PublicOrigin` (por defecto `https://localhost:7205`); al cambiar de puerto, configurar ese valor con el origen HTTPS real. La plantilla aún usa un emisor de correo simulado. En Development, abrir `/Account/RegisterConfirmation?email=<correo>` para obtener el vínculo de confirmación.

Las tres mutaciones requieren un token antiforgery además de la cookie y el permiso. La página `/users` obtiene `GET /api/security/antiforgery` y envía el token en `X-CSRF-TOKEN` con credenciales del mismo origen. Una solicitud sin token o con token inválido recibe 400. La protección de formularios de Identity permanece activa. No hay CORS abierto.

### Prueba manual en VS Code

1. Ejecutar los comandos de «Requisitos y arranque local» anteriores y entrar como Admin de Development. Abrir `https://localhost:7205/users`.
2. Pulsar **Crear usuario**, introducir un correo y una contraseña de prueba, y guardar. Confirmar que la tabla muestra el rol `User` y «Confirmado: No». Crear de nuevo con el mismo correo para comprobar el mensaje de conflicto.
3. Pulsar **Detalle**; comprobar Id, correo, confirmación y roles. Buscar el correo. Con más de diez usuarios de prueba, usar **Anterior** y **Siguiente**.
4. Pulsar **Editar**, cambiar el correo y guardar. Debe seguir sin confirmar. En Development, abrir `/Account/RegisterConfirmation?email=<correo-nuevo>` y seguir el vínculo simulado para confirmarlo.
5. Pulsar **Eliminar** sobre esa cuenta de prueba, aceptar el diálogo y comprobar que desaparece. No usar la cuenta Admin principal para una prueba destructiva. La API rechaza la autoeliminación y la eliminación del último Admin.
6. Cerrar sesión: `/users` conduce a login y las APIs devuelven 401. Con una cuenta `User`, `/users` muestra acceso denegado y las APIs del CRUD devuelven 403.

## CRUD de roles y asignaciones Usuario–Rol (E3)

| Método y ruta | Permiso | Respuesta principal |
| --- | --- | --- |
| `GET /api/roles?page=1&pageSize=10&search=` | `roles.read` | 200: lista paginada con tipo protegido y número de usuarios. Máximo 50 por página. |
| `GET /api/roles/{id}` | `roles.read` | 200: detalle; 404 si falta. |
| `POST /api/roles` | `roles.create` | 201: rol personalizado; 400/409 para nombre inválido, reservado o duplicado. |
| `PUT /api/roles/{id}` | `roles.update` | 200: rol renombrado; 400/404/409 según el caso. |
| `DELETE /api/roles/{id}` | `roles.delete` | 204: eliminación; 409 si está protegido, tiene usuarios o conserva relaciones con permisos. |
| `GET /api/users/{userId}/roles` | `users.read` **y** `roles.read` | 200: todos los roles con su estado de asignación; 404 si falta el usuario. |
| `POST /api/users/{userId}/roles/{roleId}` | `users.update` **y** `roles.update` | 200: asignación actualizada; 404/409 según el caso. |
| `DELETE /api/users/{userId}/roles/{roleId}` | `users.update` **y** `roles.update` | 200: asignación actualizada; 404/409 según el caso. |

Los nombres admiten hasta 64 caracteres y solo letras, números, punto, guion y guion bajo. `Admin` y `User` se comparan normalizados y son reservados: no se pueden recrear con variantes de mayúsculas, renombrar ni eliminar. Antes de borrar un rol personalizado, el servidor comprueba asignaciones Usuario–Rol y Rol–Permiso sin eliminar relaciones de forma implícita.

Las mutaciones requieren `X-CSRF-TOKEN`. Para asignar o revocar `Admin`, el operador debe seguir perteneciendo a `Admin` en la base de datos en ese momento. No puede autoasignarse ni revocarse su propio rol Admin, y no puede dejar al sistema sin administradores. La comprobación de autorización consulta las asignaciones y permisos actuales de SQLite en cada petición, por lo que una concesión o revocación surte efecto en la siguiente solicitud HTTP sin cerrar sesión.

### Prueba manual de E3

1. Iniciar como Admin de Development y abrir `https://localhost:7205/roles`. Comprobar que `Admin` y `User` aparecen como protegidos y no ofrecen edición ni eliminación.
2. Crear un rol personalizado, buscarlo, abrir su detalle y renombrarlo. Probar un nombre duplicado y una variante de `Admin`; deben rechazarse.
3. Abrir `/users`, mostrar el detalle de una cuenta de prueba y asignar/revocar el rol personalizado. La tabla y el detalle deben actualizarse sin un nuevo login.
4. Intentar eliminar un rol todavía asignado: debe responder 409. Revocarlo, eliminarlo y comprobar 204. No usar cuentas ni roles de producción para estas pruebas.
5. Con una cuenta sin permisos administrativos, comprobar 403. Sin sesión, comprobar 401. Para probar permisos parciales, usar una base temporal y verificar que la consulta requiere ambos permisos de lectura y la mutación ambos permisos de actualización.
6. No usar la interfaz para alterar el rol Admin de la propia cuenta. Las pruebas automatizadas cubren autoelevación, autorrevocación, operador Admin vigente y continuidad del último administrador sobre una base temporal aislada.

## Verificación automatizada

Después de compilar, desde la raíz:

```powershell
python tests/e1_smoke.py
python tests/e2_users_smoke.py
python tests/e3_roles_smoke.py
```

Las pruebas crean credenciales aleatorias solo en memoria y bases SQLite temporales, e inician el servidor por HTTPS. E1 comprueba autenticación, permisos, 429 del login y SQLite. E2 comprueba el CRUD de usuarios, permisos, validaciones, token CSRF, reconfirmación, protecciones de borrado e integridad. E3 comprueba CRUD de roles, políticas conjuntas, asignación/revocación, autorización dinámica, antiforgery, roles protegidos, restricciones de Admin y relaciones de integridad. Los procesos y las bases temporales se cierran al terminar. Python no usa el almacén de confianza de certificados de Windows en estas pruebas; los scripts omiten su validación de confianza. Se debe comprobar el certificado de desarrollo por separado con `dotnet dev-certs` y un cliente que use el almacén del sistema.

Para comprobar que el modelo coincide con la última migración:

```powershell
cd ExamenPrueba
dotnet dotnet-ef migrations has-pending-model-changes --no-build
cd ..
```

En la verificación de E1.1, el Dashboard se abrió en un navegador con JavaScript. Mostró los doce permisos y el resumen para Admin; con una cuenta User mostró cero permisos y el estado de acceso denegado. En E2 se verificaron en navegador la lista `/users`, el alta, el detalle, la búsqueda, la edición y la eliminación confirmada de una cuenta temporal. En E3 se verificaron `/roles`, la creación, edición y búsqueda de un rol personalizado, la protección visual de `Admin` y `User`, y la asignación y revocación desde `/users`. El CRUD de permisos queda para E4; el límite completo para otras rutas corresponde a E5.

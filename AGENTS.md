# ExamenPrueba: especificación y reglas de trabajo

## Flujo supervisado

- **Orquestador (ChatGPT):** arquitectura, planificación, instrucciones y revisión técnica.
- **Worker (Codex):** análisis, implementación y verificación del alcance autorizado.
- **Supervisor (usuario):** aprobación de entregas y decisiones.
- Trabajar por entregas. Detenerse al terminar cada entrega y solicitar aprobación del Supervisor antes de iniciar la siguiente.
- No hacer commits, push ni despliegues sin autorización expresa. No modificar archivos ajenos a `examen-prueba`.
- En cada entrega informar funcionalidad ejecutable, backend y frontend correspondientes, persistencia cuando aplique, verificación de autorización, pruebas y resultados comprobables, archivos modificados, problemas y riesgos pendientes. No declarar como ejecutada una prueba que no se ejecutó.

## Objetivo funcional global

ExamenPrueba implementará autenticación con ASP.NET Core Identity, registro público, inicio y cierre de sesión; CRUD de usuarios, roles y permisos; asignaciones Usuario–Rol y Rol–Permiso; autorización granular por permiso en páginas y APIs; y rate limiting configurable de ASP.NET Core.

## Arquitectura y tecnologías

- Monolito modular con capas de **presentación** (Blazor Web App, componentes Razor y Minimal APIs), **aplicación** (servicios, contratos, validaciones y reglas) e **infraestructura** (ASP.NET Core Identity, EF Core y SQLite).
- C# y .NET 10 LTS. El proyecto servidor `ExamenPrueba` aloja la aplicación y el proyecto `ExamenPrueba.Client` contiene componentes WebAssembly. Ambos se sirven desde el mismo origen.
- Mantener la autenticación y las operaciones sensibles de Identity del lado servidor. Los componentes cliente consumirán APIs mediante HTTP cuando corresponda; no accederán directamente a la base de datos.
- Usar inyección de dependencias y preferir funciones nativas de .NET. Evitar microservicios, arquitectura hexagonal completa, repositorios genéricos innecesarios y reglas de negocio en páginas Razor.
- Usar `ExamenPrueba` como raíz de namespaces, PascalCase para tipos y miembros públicos, camelCase para variables y parámetros. Nombrar servicios y contratos por su responsabilidad. Conservar la estructura de la plantilla salvo necesidad justificada.

## Modelo RBAC previsto

- Reutilizar `ApplicationUser`/`IdentityUser`, `IdentityRole` y `IdentityUserRole<string>` de Identity. Un usuario puede tener varios roles.
- Desde E1, `Permission` tiene `Id`, `Code`, `Name`, `Description`, y `RolePermission` tiene `RoleId` y `PermissionId`, clave compuesta y relaciones explícitas. Un rol puede tener varios permisos.
- Los códigos de permiso deben ser únicos y estables. Definir validaciones y reglas que impidan cambios que comprometan la seguridad, como perder el último acceso administrativo o asignar privilegios sin autorización.
- Considerar políticas basadas en permisos y un handler que resuelva permisos efectivos desde los roles del usuario. Verificar la autorización en el backend de cada API y página protegida. Ocultar controles en Blazor no autoriza una operación.

## Seguridad

- Aplicar mínimo privilegio y denegar por defecto. Validar entradas en el servidor, proteger mutaciones y gestionar los errores sin revelar información sensible.
- No versionar contraseñas, credenciales, secretos, bases de datos SQLite locales ni claves. Usar secretos de usuario o variables de entorno para valores sensibles.
- Mantener las migraciones EF Core bajo control de versiones. Revisar advertencias de seguridad de dependencias y reportar las que sigan pendientes.
- Configurar rate limiting con capacidades de ASP.NET Core, de forma verificable y configurable en las entregas previstas.

## Entregas

| Entrega | Alcance |
| --- | --- |
| E0 | Fundación técnica: solución oficial, Identity y SQLite de plantilla, migración inicial, compilación, ejecución y documentación. |
| E1 | Autenticación, protección inicial y rate limiting básico. |
| E2 | CRUD de usuarios. |
| E3 | CRUD de roles y asignaciones Usuario–Rol. |
| E4 | CRUD de permisos y asignaciones Rol–Permiso. |
| E5 | Rate limiting completo, pruebas integrales y documentación final. |

**Límite de E0:** preparar únicamente la solución e infraestructura inicial. Se pueden documentar RBAC y las fases, pero no implementar CRUD, roles personalizados, permisos, handlers, políticas propias, pantallas administrativas ni rate limiting. Conservar sin personalizar las pantallas de Identity de la plantilla. No agregar JWT, Docker, despliegue ni servicios cloud.

**Alcance de E1:** Identity con roles `Admin` y `User`, permisos iniciales persistidos, autorización por permiso en el backend, APIs mínimas, Dashboard protegido y límite de intentos POST de login. E1 no incorpora los CRUD ni la asignación interactiva de roles o permisos. La creación de una cuenta Admin requiere configuración explícita y solo funciona en Development.

**Alcance de E2:** CRUD de usuarios mediante `UserManager`, APIs protegidas por `users.read/create/update/delete`, interfaz Blazor `/users`, paginación y búsqueda. Las mutaciones JSON autenticadas por cookie exigen token antiforgery. La edición administrativa solo modifica correo; el alta asigna `User` y la eliminación física protege la cuenta propia y al último Admin. E2 no administra roles ni permisos.

**Alcance de E3:** CRUD de roles mediante `RoleManager`, APIs protegidas por `roles.read/create/update/delete`, interfaz Blazor `/roles` y gestión Usuario–Rol integrada en `/users`. Consultar asignaciones exige conjuntamente `users.read` y `roles.read`; modificarlas exige conjuntamente `users.update` y `roles.update`. `Admin` y `User` son roles protegidos, no se pueden renombrar ni eliminar. Los cambios del rol `Admin` requieren un operador que siga siendo Admin en SQLite, impiden autoasignación y autorrevocación, y preservan al último administrador. Las mutaciones exigen antiforgery. E3 no administra el catálogo ni las asignaciones de permisos.

**Alcance de E4:** CRUD de permisos personalizados y consulta del catálogo mediante `permissions.read/create/update/delete`, interfaz Blazor `/permissions` y matriz Rol–Permiso integrada en `/roles`. Los doce códigos de `PermissionCodes.All` son permisos de sistema inmutables. Consultar la matriz exige conjuntamente `roles.read` y `permissions.read`; modificarla exige conjuntamente `roles.update` y `permissions.update`, antiforgery y un operador que siga siendo Admin en SQLite. Los doce permisos base de `Admin` no se pueden retirar y el rol público `User` no puede recibirlos directamente. Los permisos personalizados no protegen automáticamente una API: el backend debe asociar explícitamente una política o requisito al endpoint.

**Alcance de E5:** rate limiting nativo con Options validadas: login 5/60 s e inscripción 3/600 s por IP de conexión; consultas administrativas 60/60 s y mutaciones 20/60 s por identificador estable de usuario. Los GET y las mutaciones de usuarios, roles, permisos y relaciones RBAC declaran su política de endpoint. El middleware se ejecuta después de autenticación y antes de autorización; devuelve 429, `Retry-After` cuando existe metadata válida y `ProblemDetails` para APIs. No confiar en cabeceras IP enviadas por clientes. E5 agrega `ExamenPrueba.Tests` con xUnit/WebApplicationFactory, `tests/e5_rate_limiting_smoke.py`, regresión integral y documentación final. Los formularios Razor de Identity siguen siendo la implementación única de registro, login y logout; no activar una autenticación REST paralela sin una entrega autorizada.

**Alcance de E5.1:** autenticación JSON mínima mediante `POST /api/auth/register`, `POST /api/auth/login` y `POST /api/auth/logout`, respaldada por el mismo servicio de aplicación que los formularios Razor. Mantener cookies Identity seguras y confirmación obligatoria; el registro público solo asigna `User`. Las tres mutaciones exigen antiforgery y el frontend existente las consume por HTTP real, conservando el POST server-side como fallback. Las rutas Razor y JSON de login/registro comparten sus contadores IP. No habilitar `MapIdentityApi`, autenticación bearer ni JWT: su conjunto general de endpoints no aplica la asignación `User` específica del proyecto.

## Comandos de trabajo

Desde la raíz del repositorio:

```powershell
dotnet restore ExamenPrueba.sln
dotnet build ExamenPrueba.sln
dotnet test ExamenPrueba.sln
dotnet run --project ExamenPrueba --launch-profile https
```

La herramienta EF está fijada en el manifiesto local `dotnet-tools.json`: ejecutar `dotnet tool restore` y, desde `ExamenPrueba`, `dotnet dotnet-ef database update` para preparar una base nueva. E1 incluye `python tests/e1_smoke.py`; E2 incluye `python tests/e2_users_smoke.py`; E3 incluye `python tests/e3_roles_smoke.py`; E4 incluye `python tests/e4_permissions_smoke.py`; E5 incluye `python tests/e5_rate_limiting_smoke.py`; E5.1 incluye `python tests/e51_auth_api_smoke.py` y las pruebas .NET de `ExamenPrueba.Tests`. Todos los tests de persistencia deben usar SQLite temporal; nunca la base local principal. Comprobar el estado real de cada comando en el reporte.

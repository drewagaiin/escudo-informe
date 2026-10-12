# Cambios

## [1.1.0] - 2026-10-12

Guía técnica de solución (segundo documento, para el técnico).

- Nueva opción `--tecnico [archivo]`: además del informe del cliente, genera una **guía técnica** con, por cada hallazgo, qué es, dónde, técnica MITRE, estándar (CIS) y los **pasos para resolverlo**.
- Base de soluciones por código (`REMEDIOS`), con respaldo por familia (ATT-, LINK-, BEC-…) y por herramienta, para que todo hallazgo tenga una recomendación.
- El correo se desglosa en sus hallazgos internos (ATT-EXEC, BEC-CONFIRMED, CRED-LINK…) en la guía técnica; el informe del cliente sigue mostrando un correo = un hallazgo.
- Se capturan MITRE y estándar de los JSON de las herramientas.
- 32 pruebas automáticas (9 nuevas para la guía técnica).

## [1.0.0] - 2026-10-08

Primera versión.

- Junta la salida JSON de ssh-sentinel, correo-escudo, cuentas-escudo y windows-escudo en un informe HTML para el dueño de la empresa.
- Nota general A–F, resumen en una frase, "qué atender primero" (alto y crítico) y detalle por herramienta.
- Lee un objeto JSON, un array o JSON Lines; acepta archivos, carpetas o la entrada estándar.
- Todo lo que viene de los informes se escapa en el HTML (sin inyección/XSS). Archivo con permisos 600, sin seguir symlinks.
- 23 pruebas automáticas y auditoría adversarial (inyección HTML y robustez con datos malformados).

# escudo-informe

Tus herramientas de seguridad sacan informes técnicos, cada una por su lado. Pero el dueño de una empresa no quiere leer cuatro JSON: quiere **una página que le diga qué tan mal está y qué arreglar primero**.

**escudo-informe** junta la salida de ssh-sentinel, correo-escudo, cuentas-escudo y windows-escudo en **un solo informe HTML** para el dueño: una nota general (A–F), lo más urgente, y el detalle por herramienta.

Y con `--tecnico` genera **un segundo documento para el técnico**: la misma lista de hallazgos pero con el **cómo resolver** de cada uno (pasos, técnica MITRE y estándar CIS). Así entregas uno al cliente y te quedas con tu guía de trabajo.

Es un script de **Python**. No usa internet. Solo lee los archivos que le das.

## Lo más cómodo: un solo comando

`escudo-reporte.sh` corre tus herramientas, junta los JSON y arma los dos informes solo:
```bash
./escudo-reporte.sh --empresa "Ferretería El Clavo" --dominio elclavo.com --cuentas logins.csv --abrir
```
Guarda todo en `~/escudo-reportes/FECHA/` (cliente, técnico y los datos). Opciones: `--dominio`, `--correo`, `--cuentas`, `--windows`, `--pais`, `--no-ssh`, `--abrir`. Corre solo las herramientas que tengas instaladas.

## Cómo se usa (paso a paso)

Primero genera la salida JSON de cada herramienta:
```bash
sudo ssh-sentinel --format json            > ssh.json
correo-escudo analizar correos/ --format json > correo.json
cuentas-escudo logins.csv --salida json    > cuentas.json
# en Windows:  .\windows-escudo.ps1 -Json  > windows.json
```

Y arma el informe:
```bash
./escudo-informe.py ssh.json correo.json cuentas.json windows.json -o informe.html --empresa "Ferretería El Clavo"
```
O apúntale a una carpeta con todos los JSON, y pide también la guía técnica:
```bash
./escudo-informe.py resultados/ -o informe.html --tecnico --empresa "Mi Cliente"
```
Eso crea dos archivos: `informe.html` (para el cliente) e `informe-tecnico.html` (tu guía de solución). También puedes darle un nombre: `--tecnico guia.html`.

Abre `informe.html` en cualquier navegador. Se ve bien y se puede imprimir o guardar como PDF (Ctrl+P → Guardar como PDF).

**Códigos de salida:** `0` bien · `1` mejorable · `3` grave · `2` error.

## Qué necesita

Solo **Python 3** (3.9 o más nuevo). Nada que instalar: usa la librería estándar.

## Qué hace (y qué no)

- Junta hallazgos de las cuatro herramientas, los pone en una escala única (crítico → bajo) y calcula una nota.
- Muestra "qué atender primero" (solo lo alto y crítico) y el detalle por herramienta.
- Con `--tecnico`, genera una guía de solución con los pasos para arreglar cada hallazgo.
- **No** vuelve a analizar nada: solo resume lo que las herramientas ya encontraron.
- **No** garantiza seguridad: el informe dice lo detectado en esa fecha, no que todo esté bien.

## Seguridad del propio informe

Todo lo que viene de los JSON (títulos, equipos, usuarios) se **escapa** antes de meterlo en el HTML, así un dato malicioso no puede inyectar código en el informe. El archivo se guarda con permisos 600 y no sigue enlaces simbólicos.

## Cómo se ha probado

32 pruebas automáticas (normalización de los 4 formatos, cálculo de la nota, generación del HTML del cliente y de la guía técnica, base de soluciones y seguridad). Auditoría adversarial que confirmó que no hay inyección HTML (XSS) ni cuelgues con datos malformados.

## Parte de un kit

Es el "remate" de [ssh-sentinel](https://github.com/drewagaiin/ssh-sentinel), [correo-escudo](https://github.com/drewagaiin/correo-escudo), [cuentas-escudo](https://github.com/drewagaiin/cuentas-escudo) y [windows-escudo](https://github.com/drewagaiin/windows-escudo): convierte cuatro revisiones técnicas en un informe que el dueño entiende.

Licencia [MIT](LICENSE). Hecho por Andrés Clark en Panamá.

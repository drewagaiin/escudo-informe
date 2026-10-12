# Seguridad

## Si encontraste un fallo
Avísame por **Security → Report a vulnerability** en GitHub. Respuesta en una semana como mucho. Un falso positivo no es una vulnerabilidad: ábrelo como issue normal.

## Lo que el programa promete
- **Solo lee.** Toma los JSON que le das y escribe un archivo HTML. No se conecta a internet ni analiza nada por su cuenta.
- **El informe es seguro de abrir.** Todo lo que viene de los datos (títulos, equipos, usuarios, nombre de la empresa) se escapa antes de ponerlo en el HTML, así un informe con texto malicioso no puede ejecutar código en tu navegador (XSS).
- **No se cae con datos malformados.** Un JSON roto, una línea basura o un campo con tipo raro se saltan; nunca termina con un error de Python.
- **Tu informe es tuyo.** Se guarda con permisos 600 y no sigue enlaces simbólicos.

## Lo que no promete
No es un análisis: solo resume lo que las otras herramientas ya encontraron. Que diga "BIEN" significa que no hubo hallazgos en lo revisado, no que la empresa sea segura.

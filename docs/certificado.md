# Confiar el certificado de la CA interna

Caddy genera su propia autoridad de certificacion (CA) la primera vez que
arranca, porque no hay un dominio publico al que pedir un certificado de pago.
El navegador no conoce esa CA, asi que la primera vez veras un aviso de
seguridad. **Es lo esperado**, y se resuelve confiando el certificado raiz.

> No instales nada en el sistema. Solo se importa un certificado, que es una
> operacion del sistema operativo o del navegador, no una instalacion de
> software.

## 1. Exportar el certificado

Con el stack levantado:

```bash
npm run trust
```

Deja el fichero `caddy-root.crt` en la raiz del repositorio (esta en
`.gitignore` a proposito).

## 2. Importarlo en tu navegador

### Chrome, Edge, Brave, Opera (Chromium)

1. Abre `chrome://settings/security` (o `edge://settings/security`).
2. Baja a **Administrar certificados**.
3. **Autoridades de certificacion raiz de confianza** -> **Importar**.
4. Selecciona `caddy-root.crt` y acepta.

Se guarda en el almacen **del usuario actual**, asi que **no hace falta ser
administrador**. Es la via recomendada.

> En Chrome el boton es "Importar" dentro de "Administrar certificados"; en
> algunas versiones aparece como "Certificados authorities" en el buscador.

### Firefox

1. Ajustes -> **Privacidad y seguridad**.
2. Abajo del todo: **Ver certificados...**
3. Pestana **Autoridades** -> **Importar...**
4. Selecciona `caddy-root.crt`.
5. Activa la casilla **"Confiar en esta CA para identificar sitios web"**.

Firefox tiene su propio almacen, asi que el certificado hay que importarlo
**una vez por Firefox**, aunque ya lo hayas importado en Chrome.

### Safari (macOS)

Doble clic sobre `caddy-root.crt` -> **Keychain Access** -> categoria
**Certificados** -> categoria **Autoridades** -> doble clic en el certificado
-> **Confiar siempre**.

## 3. Acceder a la aplicacion

```
https://localhost:8443
```

El candado de la barra de direcciones ya deberia verse sin aviso.

## Si prefieres no confiar la CA

`localhost` es un **contexto seguro** por definicion: el navegador expone
`crypto.subtle` sin necesidad de TLS. Y Caddy no publica ningun otro puerto
que el 8443.

**Pero:** si accedes desde la IP del servidor (por ejemplo
`https://192.168.1.50:8443` desde el movil), `localhost` ya no aplica y sin un
certificado confiable el navegador **no expone `crypto.subtle`**, y SecureKey te
avisara de que el contexto no es seguro. En ese caso, o confias la CA en el
dispositivo desde el que te conectas, o usas un dominio real con un
certificado emitido por una CA publica.

## Si cambias de dominio

`localhost:8443` esta escrito en tres sitios. Si quieres otro origen, cambialos
los tres y vuelve a arrancar:

| Fichero | Que cambiar |
|---|---|
| `infra/caddy/Caddyfile` | `https://localhost:8443 {` |
| `infra/caddy/Caddyfile.dev` | `https://localhost:8443 {` |
| `.env` | `APP_ORIGIN` y `ALLOWED_ORIGINS` |

Caddy emite un certificado nuevo para el nuevo host automaticamente.

## Comprobar que todo va bien

```bash
npm run test:http
```

Verifica, entre otras cosas, que la CSP se sirve sin `unsafe-inline` y que la
API responde a traves del proxy. Sale por pantalla lo que ha comprobado.

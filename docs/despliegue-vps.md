# Despliegue en una VPS con nginx ya instalado

Guía para `securekey.yal99.com` en una VPS que **ya sirve otras aplicaciones con
nginx**. Es el caso real: hay un `nginx-proxy` ocupando los puertos 80 y 443, y
las demás apps no se tocan.

## Qué monta este despliegue

```
Internet ──TLS(443)── Caddy ──red edge── web (nginx, estático)
                                  └──red backend (sin salida)── api ── db
```

Caddy es el único que escucha hacia Internet, y solo en el **443**.

---

## Antes de nada: por qué no es el despliegue normal

La receta habitual (`Caddyfile.prod` con el desafío HTTP-01) necesita el puerto
80. Aquí no está libre: es del nginx que sirve las otras apps. Por eso este
despliegue usa el **desafío DNS-01**, que no necesita ningún puerto, y por eso
pide un API Token de Cloudflare.

Dos consecuencias que conviene tener claras:

- **Caddy solo publica el 443.** El 80 sigue siendo de nginx.
- **El registro DNS va en "solo DNS" (nube gris).** Si activaras el proxy de
  Cloudflare, el navegador nunca llegaría a este Caddy y el certificado dejaría
  de tener sentido.

---

## Paso 1 — Cloudflare

### 1.1 El registro DNS

**DNS → Records → Add record**

| Campo | Valor |
| --- | --- |
| Type | `A` |
| Name | `securekey` |
| IPv4 address | la IP de la VPS (`62.171.157.89`) |
| Proxy status | **DNS only** (nube gris) |
| TTL | Auto |

> Si eliges nube naranja, Cloudflare se queda el tráfico y tu Caddy no recibe
> nada. Funciona, pero el certificado público sobra y pierdes la IP real del
> cliente en el `audit_log`.

Compruébalo antes de seguir:

```bash
nslookup securekey.yal99.com
```

Debe devolver **la IP de tu VPS**, no una de Cloudflare (tipo `172.67.x.x`).

### 1.2 El API Token para el certificado

**My Profile → API Tokens → Create Token → Custom token**

| Permiso | Recurso |
| --- | --- |
| `Zone` / `DNS` / `Edit` | `Include` / `Specific zone` / `yal99.com` |

Cópialo. Lo necesitas en el paso 3. **No pongas el token de la API global de
Cloudflare**: el permiso DNS:Edit de esa cuenta alcanza todas tus zonas.

---

## Paso 2 — Liberar el 443 en la VPS

nginx publica el 443 pero **nada escucha dentro** (sus tres vhosts solo tienen
`listen 80`). Se comprueba antes de tocar nada:

```bash
ss -tlnp | grep :443
curl -kI --max-time 5 https://62.171.157.89/
```

Lo segundo no debe devolver nada.

Copia de seguridad y cambio:

```bash
cd /opt/apps/nginx
cp docker-compose.yml docker-compose.yml.bak
sed -i '/"443:443"/d' docker-compose.yml
docker compose config | grep -A3 published   # comprueba que solo queda el 80
docker compose up -d
```

Esto recrea **un** contenedor, el `nginx-proxy`. Los proyectos `jwaddresses` y
`paulinayalfred` no se tocan: son proyectos de compose distintos y no se
invocan. La interrupción es de 1 a 3 segundos.

### 2.1 La redirección del 80

Sin esto, `http://securekey.yal99.com` cae en el primer `server` de nginx
(`jwaddresses.conf`, que es el primero en orden alfabético) y **serviría la otra
aplicación bajo el nombre de este dominio**.

```bash
cat > /opt/apps/nginx/conf.d/securekey.conf <<'EOF'
server {
    listen 80;
    server_name securekey.yal99.com;
    # Este vhost solo existe para eso: el 443 lo sirve SecureKey.
    return 301 https://$host$request_uri;
}
EOF

docker exec nginx-proxy nginx -t && docker exec nginx-proxy nginx -s reload
```

`conf.d` está montado como volumen, así que **no hace falta recrear nada**: el
reload no interrumpe ni un segundo.

---

## Paso 3 — SecureKey

```bash
cd /opt/apps
git clone <tu-repo> securekey
cd securekey
npm run secrets
```

Edita el `.env`:

```bash
APP_HOST=securekey.yal99.com
APP_ORIGIN=https://securekey.yal99.com
ALLOWED_ORIGINS=https://securekey.yal99.com
CF_API_TOKEN=<el token del paso 1.2>
```

`npm run secrets` rellena los secretos (contraseñas, pepper, clave de
invitaciones) y **no toca** estas cuatro. Puedes editar el `.env` antes o
después: da igual.

> Si se te olvida `APP_ORIGIN` o `ALLOWED_ORIGINS`, la API responde **403 al
> registro y al login**. El hook `onRequest` rechaza cualquier `Origin` fuera
> de la lista.

Arranque:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

El primer `--build` tarda unos minutos: compila la imagen de Caddy con el módulo
de DNS de Cloudflare. Los siguientes tardan segundos.

---

## Paso 4 — Comprobar

```bash
# 1. El certificado es real y de la CA correcta
curl -vI https://securekey.yal99.com 2>&1 | grep -E "subject|issuer|SSL connection"

# 2. Caddy está sirviendo y no hay errores
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs caddy | tail -20

# 3. La API responde
curl https://securekey.yal99.com/api/v1/health

# 4. Tus otras apps siguen igual
curl -I http://jwaddresses.yal99.com
curl -I http://paulina-yalfred.yal99.com
```

Lo que esperas del primer comando:

```
subject: CN=securekey.yal99.com
issuer: C=US, O=Let's Encrypt, CN=R11
SSL connection using TLSv1.3
```

Y en el log de Caddy, una línea con `certificate obtained successfully`.

### Primer usuario

El registro está cerrado por defecto, así que **hay que invitar**:

```bash
npm run invite -- tu@correo.com
```

---

## Paso 5 — Backups

```bash
npm run backup          # primer volcado, verificado
npm run backup:cron     # queda instalado a diario a las 04:17
```

> Aviso: quedan en `./backups`, en el mismo disco. Eso protege de errores
> humanos (un `down -v` sin querer), **no de que muera el disco**. Cuando
> quieras sacarlos: `BACKUP_DIR=/mnt/nas npm run backup`.

---

## Actualizar

```bash
cd /opt/apps/securekey
git pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Caddy renueva el certificado solo, cada 30 días. No hay nada que hacer, pero si
algún día el token caduca **no te vas a enterar hasta que el certificado
caduque**. Para vigilarlo:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs caddy | grep -i "certificate\|obtain"
```

---

## Volver atrás

El orden importa: si Caddy tiene el 443, restaurarlo en nginx chocaría.

```bash
cd /opt/apps/securekey
docker compose -f docker-compose.yml -f docker-compose.prod.yml down

cd /opt/apps/nginx
cp docker-compose.yml.bak docker-compose.yml
docker compose up -d
rm conf.d/securekey.conf
docker exec nginx-proxy nginx -s reload
```

---

## Lo que este despliegue NO arregla

Las otras aplicaciones siguen en modo **Flexible**: de Cloudflare a tu VPS van
sin cifrar, y pueden acceder al puerto 80 saltándose Cloudflare.

Eso incluye `jwaddresses`, donde las credenciales de login viajan en claro en
ese tramo. Es un salto corto, entre Cloudflare y tu datacenter, así que no está
expuesto a un atacante cualquiera, pero es un defecto de diseño real.

Arreglarlo significa que **nginx pase a tener el 443** con certificados de Let's
Encrypt para todos los dominios, y que SecureKey entre por detrás. Eso cambia la
topología de este documento. Es un trabajo aparte, y no bloquea nada de lo
anterior.

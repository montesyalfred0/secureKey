/** Punto de entrada del proceso. */
import { loadConfig } from './config.js';
import { buildApp } from './app.js';
import { closePool, getPool } from './db/pool.js';

async function main(): Promise<void> {
  const config = loadConfig();
  const app = await buildApp(config);

  // Cierre ordenado: dejamos de aceptar conexiones, cerramos el pool y solo
  // entonces salimos. Sin esto, `docker compose down` cortaria conexiones a
  // medias y las peticiones en vuelo fallarian.
  const shutdown = async (signal: string): Promise<void> => {
    app.log.info({ signal }, 'apagando');
    try {
      await app.close();
      await closePool();
      process.exit(0);
    } catch (error) {
      app.log.error({ err: error }, 'error durante el apagado');
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('unhandledRejection', (reason) => {
    app.log.fatal({ err: reason }, 'promesa rechazada sin manejar');
  });
  process.on('uncaughtException', (error) => {
    app.log.fatal({ err: error }, 'excepcion no capturada');
    void shutdown('uncaughtException');
  });

  // Fallamos rapido si la base de datos no responde al arrancar.
  await getPool(config).query('SELECT 1');

  await app.listen({ host: config.host, port: config.port });
  app.log.info(
    { port: config.port, env: config.nodeEnv, registration: config.registrationMode },
    'SecureKey API escuchando',
  );
}

main().catch((error: unknown) => {
  // Todavia no hay logger: escribimos en stderr y salimos con codigo 1 para
  // que el orquestador reinicie el contenedor.
  console.error('No se pudo iniciar SecureKey API:', error instanceof Error ? error.message : error);
  process.exit(1);
});

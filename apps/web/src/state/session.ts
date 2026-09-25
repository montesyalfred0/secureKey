/**
 * Estado de sesion y orquestacion de la boveda.
 *
 * La `vaultKey` vive en un REF, nunca en un estado de Preact: el estado acaba
 * en el arbol de la interfaz y es trivial de inspeccionar desde las
 * herramientas del navegador. Aqui solo hay un puntero opaco, y el array de
 * 32 bytes se borra con `wipe()` al bloquear.
 */
import { useCallback, useEffect, useRef, useState } from 'preact/hooks';
import type { KdfParams, LoginResponse } from '@securekey/shared';
import * as api from '../lib/api.js';
import { ApiError } from '../lib/api.js';
import {
  deriveAccountKeys,
  deriveMasterKey,
  decryptItem,
  encryptItem,
  generateVaultKey,
  toB64,
  unwrapVaultKey,
  wipe,
  wrapVaultKey,
  type ItemPlain,
} from '../lib/crypto.js';
import { cancelAutoClear } from '../lib/clipboard.js';
import { toast } from './toasts.js';

export type Phase = 'boot' | 'auth' | 'locked' | 'vault';

export type DecryptedItem = {
  id: string;
  version: number;
  plain: ItemPlain;
  updatedAt: string;
  createdAt: string;
};

/** Error de dominio: mensaje apto para mostrar al usuario. */
export class SecureKeyError extends Error {}

function humanize(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof SecureKeyError) return error.message;
  if (error instanceof Error) {
    // Un fallo de AEAD al desenvolver significa contrasena maestra incorrecta
    // o datos corruptos. El mensaje tecnico no ayuda a nadie.
    if (/decrypt|operation-specific|unable to decrypt|authenticate/i.test(error.message)) {
      return 'Contrasena maestra incorrecta o datos de la boveda danados';
    }
    return error.message;
  }
  return 'Error inesperado';
}

export function useSecureKey() {
  const [phase, setPhase] = useState<Phase>('boot');
  const [email, setEmail] = useState('');
  const [kdf, setKdf] = useState<KdfParams | null>(null);
  const [keyVersion, setKeyVersion] = useState(1);
  const [busy, setBusy] = useState(false);

  const vaultKeyRef = useRef<Uint8Array | null>(null);
  const emailRef = useRef('');
  const keyVersionRef = useRef(1);
  const kdfRef = useRef<KdfParams | null>(null);

  const setRefs = useCallback((mail: string, version: number, params: KdfParams | null) => {
    emailRef.current = mail;
    keyVersionRef.current = version;
    kdfRef.current = params;
  }, []);

  const enterVault = useCallback((mail: string, version: number, params: KdfParams | null) => {
    setEmail(mail);
    setKeyVersion(version);
    setKdf(params);
    setRefs(mail, version, params);
    setPhase('vault');
  }, [setRefs]);

  // --- Arranque: ¿hay sesion valida? -------------------------------------
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const session = await api.currentSession();
        if (cancelled) return;
        if (session.authenticated && session.user) {
          setEmail(session.user.email);
          setRefs(session.user.email, 1, null);
          // La cookie de sesion sobrevive a un recargado; la clave de boveda no.
          setPhase('locked');
        } else {
          setPhase('auth');
        }
      } catch {
        if (!cancelled) setPhase('auth');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [setRefs]);

  /** Re-envuelve la MISMA vaultKey con una KEK derivada de la nueva KDF. */
  const performRekey = useCallback(
    async (newKdf: KdfParams, masterKey: Uint8Array, authKey: Uint8Array, vaultKey: Uint8Array) => {
      const { kek } = await deriveAccountKeys(masterKey, emailRef.current);
      const wrapped = await wrapVaultKey(vaultKey, kek, emailRef.current, keyVersionRef.current);
      await api.rekey({ authKey: toB64(authKey), vault: wrapped, kdfVersion: newKdf.version });
    },
    [],
  );

  const finishLogin = useCallback(
    async (
      response: LoginResponse,
      masterKey: Uint8Array,
      authKey: Uint8Array,
      currentKdf: KdfParams,
      vaultKey: Uint8Array,
    ) => {
      if (response.needsVaultRekey) {
        await performRekey(currentKdf, masterKey, authKey, vaultKey);
        toast.info('Parametros de derivacion actualizados. Tu boveda se ha re-cifrado.');
      }
      vaultKeyRef.current = vaultKey;
      enterVault(response.user.email, response.keyVersion, currentKdf);
    },
    [enterVault, performRekey],
  );

  // --- Acciones publicas -------------------------------------------------

  const signIn = useCallback(
    async (mail: string, password: string) => {
      setBusy(true);
      try {
        const pre = await api.prelogin(mail);
        if (!pre.exists) throw new SecureKeyError('No existe ninguna cuenta con ese correo');
        if (pre.lockedUntil !== null) {
          throw new SecureKeyError('Cuenta bloqueada por intentos fallidos. Intentalo mas tarde.');
        }

        const masterKey = await deriveMasterKey(password, mail, pre.kdf);
        const { kek, authKey } = await deriveAccountKeys(masterKey, mail);
        const response = await api.login({
          email: mail,
          authKey: toB64(authKey),
          kdfVersion: pre.kdf.version,
        });
        if (response.vault === null) throw new SecureKeyError('La cuenta no tiene boveda inicializada');

        const vaultKey = await unwrapVaultKey(
          response.vault,
          kek,
          mail,
          response.keyVersion,
        );
        await finishLogin(response, masterKey, authKey, pre.kdf, vaultKey);
      } catch (error) {
        throw new SecureKeyError(humanize(error));
      } finally {
        setBusy(false);
      }
    },
    [finishLogin],
  );

  const signUp = useCallback(
    async (mail: string, password: string, inviteCode?: string) => {
      setBusy(true);
      try {
        const pre = await api.prelogin(mail);
        if (pre.exists) throw new SecureKeyError('Ya existe una cuenta con ese correo');

        const masterKey = await deriveMasterKey(password, mail, pre.kdf);
        const { kek, authKey } = await deriveAccountKeys(masterKey, mail);
        const vaultKey = generateVaultKey();
        const wrapped = await wrapVaultKey(vaultKey, kek, mail, 1);

        const response = await api.register({
          email: mail,
          authKey: toB64(authKey),
          vault: wrapped,
          kdf: pre.kdf,
          ...(inviteCode !== undefined && inviteCode.length > 0 ? { inviteCode } : {}),
        });

        vaultKeyRef.current = vaultKey;
        enterVault(response.user.email, response.keyVersion, pre.kdf);
        toast.success('Cuenta creada. Tu boveda vive cifrada en este dispositivo.');
      } catch (error) {
        throw new SecureKeyError(humanize(error));
      } finally {
        setBusy(false);
      }
    },
    [enterVault],
  );

  const unlock = useCallback(
    async (password: string) => {
      setBusy(true);
      try {
        const mail = emailRef.current;
        const pre = await api.prelogin(mail);
        const masterKey = await deriveMasterKey(password, mail, pre.kdf);
        const { kek, authKey } = await deriveAccountKeys(masterKey, mail);
        const response = await api.unlock({ authKey: toB64(authKey), kdfVersion: pre.kdf.version });
        const vaultKey = await unwrapVaultKey(response.vault, kek, mail, response.keyVersion);

        if (response.needsVaultRekey) {
          await performRekey(pre.kdf, masterKey, authKey, vaultKey);
        }
        vaultKeyRef.current = vaultKey;
        enterVault(mail, response.keyVersion, pre.kdf);
      } catch (error) {
        throw new SecureKeyError(humanize(error));
      } finally {
        setBusy(false);
      }
    },
    [enterVault, performRekey],
  );

  const lock = useCallback(() => {
    wipe(vaultKeyRef.current);
    vaultKeyRef.current = null;
    cancelAutoClear();
    setPhase('locked');
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      // Si la sesion ya no existe en el servidor, cerrar localmente es igual.
    }
    wipe(vaultKeyRef.current);
    vaultKeyRef.current = null;
    cancelAutoClear();
    setEmail('');
    setKdf(null);
    emailRef.current = '';
    setPhase('auth');
  }, []);

  const changeMasterPassword = useCallback(
    async (currentPassword: string, newPassword: string) => {
      const mail = emailRef.current;
      const currentKdf = kdfRef.current;
      const vaultKey = vaultKeyRef.current;
      if (currentKdf === null || vaultKey === null) {
        throw new SecureKeyError('La boveda esta bloqueada');
      }

      const pre = await api.prelogin(mail);
      const currentMaster = await deriveMasterKey(currentPassword, mail, pre.kdf);
      const current = await deriveAccountKeys(currentMaster, mail);

      // Se derivan las NUEVAS claves con los parametros vigentes del servidor.
      const newMaster = await deriveMasterKey(newPassword, mail, pre.kdf);
      const next = await deriveAccountKeys(newMaster, mail);
      const wrapped = await wrapVaultKey(vaultKey, next.kek, mail, keyVersionRef.current);

      await api.changeMasterPassword({
        currentAuthKey: toB64(current.authKey),
        newAuthKey: toB64(next.authKey),
        newVault: wrapped,
        kdfVersion: pre.kdf.version,
      });

      setKdf(pre.kdf);
      kdfRef.current = pre.kdf;
      toast.success('Contrasena maestra actualizada. Ningun item ha tenido que re-cifrarse.');
    },
    [],
  );

  // --- Boveda descifrada --------------------------------------------------

  const [items, setItems] = useState<DecryptedItem[]>([]);
  const [itemsBusy, setItemsBusy] = useState(false);
  const [itemsError, setItemsError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    const vaultKey = vaultKeyRef.current;
    if (vaultKey === null) return;

    setItemsBusy(true);
    setItemsError(null);
    try {
      const dtos = await api.listItems();
      const version = keyVersionRef.current;
      const decrypted = await Promise.all(
        dtos.map(async (dto) => {
          const plain = await decryptItem(vaultKey, dto.id, version, dto.blob);
          return {
            id: dto.id,
            version: dto.version,
            plain,
            createdAt: dto.createdAt,
            updatedAt: dto.updatedAt,
          };
        }),
      );
      decrypted.sort((a, b) => a.plain.title.localeCompare(b.plain.title, 'es'));
      setItems(decrypted);
    } catch (error) {
      setItemsError(humanize(error));
    } finally {
      setItemsBusy(false);
    }
  }, []);

  const createItem = useCallback(async (plain: ItemPlain) => {
    const vaultKey = vaultKeyRef.current;
    if (vaultKey === null) throw new SecureKeyError('La boveda esta bloqueada');
    // El id lo genera el cliente porque forma parte del AAD del cifrado.
    const id = crypto.randomUUID();
    const blob = await encryptItem(vaultKey, id, keyVersionRef.current, plain);
    await api.createItem(id, blob);
    await reload();
  }, [reload]);

  const updateItem = useCallback(async (id: string, version: number, plain: ItemPlain) => {
    const vaultKey = vaultKeyRef.current;
    if (vaultKey === null) throw new SecureKeyError('La boveda esta bloqueada');
    const blob = await encryptItem(vaultKey, id, keyVersionRef.current, plain);
    await api.updateItem(id, blob, version);
    await reload();
  }, [reload]);

  const removeItem = useCallback(async (id: string) => {
    await api.deleteItem(id);
    await reload();
  }, [reload]);

  return {
    phase,
    email,
    kdf,
    keyVersion,
    busy,
    signIn,
    signUp,
    unlock,
    lock,
    logout,
    changeMasterPassword,
    items,
    itemsBusy,
    itemsError,
    reload,
    createItem,
    updateItem,
    removeItem,
  };
}

export type SecureKeyStore = ReturnType<typeof useSecureKey>;

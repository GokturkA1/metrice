import { readFileSync } from 'node:fs';

/**
 * Metrice Dinamik Sürüm ve Protokol Tanımlayıcı Sistemi
 * package.json dosyasını dinamik olarak okuyarak SSH sunucu kimlik dizgesi
 * ve uygulama sürümünü merkezi olarak yönetir. Böylece sürüm güncellemelerinde
 * kod tabanında veya testlerde elle versiyon dizgesi güncelleme ihtiyacını ortadan kaldırır.
 */

let packageVersion = '2.5.0';
try {
  const packageJsonUrl = new URL('../package.json', import.meta.url);
  const pkg = JSON.parse(readFileSync(packageJsonUrl, 'utf-8'));
  if (pkg && typeof pkg.version === 'string' && pkg.version.trim().length > 0) {
    packageVersion = pkg.version.trim();
  }
} catch {
  // Fallback: Dosya sistemi okunamadığı takdirde son bilinen sürüm kullanılır
}

export const APP_NAME = 'Metrice';
export const VERSION = packageVersion;
export const DEFAULT_SSH_SERVER_VERSION = `SSH-2.0-${APP_NAME}_${VERSION}`;

/**
 * Mevcut uygulama sürümünü döner
 * @returns {string}
 */
export function getVersion() {
  return VERSION;
}

/**
 * Varsayılan SSH-2 sunucu protokol kimlik dizgesini döner
 * @returns {string}
 */
export function getDefaultSshServerVersion() {
  return DEFAULT_SSH_SERVER_VERSION;
}

/**
 * Verilen özel veya yapılandırılmış SSH sunucu sürümünü standart formatta biçimlendirir.
 * Eğer özel sürüm belirtilmemişse varsayılan sürüm dizgesini döner.
 * @param {string} [customVersion]
 * @returns {string}
 */
export function formatSshServerVersion(customVersion) {
  if (typeof customVersion === 'string' && customVersion.trim().length > 0) {
    const clean = customVersion.trim();
    return clean.startsWith('SSH-2.0-') ? clean : `SSH-2.0-${clean}`;
  }
  return DEFAULT_SSH_SERVER_VERSION;
}

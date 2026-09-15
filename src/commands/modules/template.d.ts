import type { TerminalSession } from '../../core/terminalSession.d.ts';
import type { Database } from '../../storage/database.d.ts';
import type { FederationEngine } from '../../core/federation.d.ts';
import type { ClientServer } from '../../core/clientServer.d.ts';
import type { CommandRegistry } from '../commandRegistry.d.ts';
import type { Socket } from 'node:net';

/**
 * Komut calistirma baglami (execute context).
 * Bir komut cagrildiginda execute metoduna iletilen parametreler.
 */
export interface CommandExecutionContext {
  /** Komuta gecilen parametre dizisi (/msg @alice merhaba -> ['@alice', 'merhaba']) */
  args: string[];
  /** Komut adindan sonra gelen ham arguman dizgesi */
  argStr: string;
  /** Komutu cagiran kullanicinin aktif TUI terminal oturumu */
  session: TerminalSession;
  /** Oturumun bagli oldugu ag soketi (TCP socket veya virtual socket) */
  socket?: Socket | any;
  /** Yerel veritabani ornegi */
  db: Database;
  /** P2P Federasyon ve ag motoru ornegi */
  federation?: FederationEngine;
  /** TUI ve istemci sunucusu ornegi */
  clientServer?: ClientServer;
  /** Kayitli komutlar yoneticisi */
  registry?: CommandRegistry;
  /** Komutu calistiran kullanicinin tam adresi (@nick:node.mesh) */
  userAddress: string;
}

/**
 * Komut modulu tanim sablonu.
 * commands/modules altindaki her bir komut dosyasi bu arayuzu varsayilan olarak disari aktarmalidir (export default).
 */
export interface CommandDefinition {
  /** Komutun birincil adi (ornek: 'clear', 'msg', 'join') */
  name: string;
  /** Komutun alternatif kisayollari veya takma adlari (ornek: ['cls'], ['m', 'w']) */
  aliases?: string[];
  /** Komutun amaci ve islevi hakkinda kisa aciklama (I18n ile yerellestirilmis dizge onerilir) */
  description: string;
  /** Komut kullanim sozdimi ornegi (ornek: '/msg <hedef> <mesaj>') */
  usage?: string;
  /** Komut kategorisi (ornek: 'general', 'messaging', 'channel', 'security', 'system') */
  category?: 'general' | 'messaging' | 'channel' | 'security' | 'system' | string;
  /**
   * Komutun ana calistirma fonksiyonu.
   * Senkron veya Asenkron (Promise) olarak uygulanabilir.
   */
  execute: (context: CommandExecutionContext) => void | Promise<void>;
}

declare const commandTemplate: CommandDefinition;
export default commandTemplate;

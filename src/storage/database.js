import fs from 'node:fs';
import { Logger } from '../utils/logger.js';
import { I18n } from '../locales/i18n.js';

const log = new Logger('DATABASE');

export class Database {
  constructor(filepath) {
    this.filepath = filepath;
    this.data = { profiles: {}, messages: [], outbox: [] };
    this.saveTimeout = null;
    this.init();
  }

  init() {
    if (fs.existsSync(this.filepath)) {
      try {
        this.data = JSON.parse(fs.readFileSync(this.filepath, 'utf-8'));
        if (!this.data.profiles) this.data.profiles = {};
        if (!this.data.outbox) this.data.outbox = [];
        log.info(I18n.t('DB_LOADED', { path: this.filepath }), { mesajSayisi: this.data.messages.length });
      } catch (err) {
        log.error(I18n.t('DB_CORRUPT_RESET', { error: err.message }));
        this.scheduleSave(true);
      }
    } else {
      log.info(I18n.t('DB_CREATED', { path: this.filepath }));
      this.scheduleSave(true);
    }
  }

  scheduleSave(immediate = false) {
    if (this.saveTimeout) clearTimeout(this.saveTimeout);

    const performSave = async () => {
      try {
        await fs.promises.writeFile(this.filepath, JSON.stringify(this.data, null, 2), 'utf-8');
      } catch (err) {
        log.error(I18n.t('DB_WRITE_ERROR', { error: err.message }));
      }
    };

    if (immediate) performSave();
    else this.saveTimeout = setTimeout(performSave, 150);
  }

  getUserProfile(userAddress) {
    if (!this.data.profiles[userAddress]) {
      this.data.profiles[userAddress] = {
        contacts: ['*sistem', '#genel'],
        history: []
      };
      this.scheduleSave(false);
    }
    return this.data.profiles[userAddress];
  }

  updateUserProfile(userAddress, contacts, history) {
    this.data.profiles[userAddress] = {
      contacts: Array.from(new Set(contacts)),
      history: history.slice(-50) // Son 50 komut
    };
    this.scheduleSave(false);
  }

  saveMessage({ id, from, to, content, isAction = false, isSnippet = false, timestamp = new Date().toISOString() }) {
    const messageId = id || `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const exists = this.data.messages.some((m) => m.id === messageId);
    if (exists) return null;

    const record = {
      id: messageId,
      from,
      to,
      content,
      isAction,
      isSnippet,
      timestamp
    };
    this.data.messages.push(record);
    this.scheduleSave(false);
    log.debug(I18n.t('DB_MSG_SAVED'), { id: record.id, from, to });
    return record;
  }

  queueOutbox(message) {
    this.data.outbox.push({
      ...message,
      retries: 0,
      nextRetry: Date.now() + 5000
    });
    this.scheduleSave(false);
  }

  getPendingOutbox() {
    const now = Date.now();
    return this.data.outbox.filter((item) => item.nextRetry <= now);
  }

  removeOutbox(id) {
    this.data.outbox = this.data.outbox.filter((item) => item.id !== id);
    this.scheduleSave(false);
  }

  updateOutboxRetry(id) {
    const item = this.data.outbox.find((i) => i.id === id);
    if (item) {
      item.retries += 1;
      const delay = Math.min(120000, 5000 * Math.pow(2, item.retries));
      item.nextRetry = Date.now() + delay;
      this.scheduleSave(false);
    }
  }

  getConversation(targetA, targetB) {
    if (!targetB) return [];

    if (targetB.startsWith('#')) {
      return this.data.messages.filter((m) => m.to === targetB);
    }

    return this.data.messages.filter(
      (m) => (m.from === targetA && m.to === targetB) || (m.from === targetB && m.to === targetA)
    );
  }
}
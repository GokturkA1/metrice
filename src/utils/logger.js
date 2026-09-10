import fs from 'node:fs';
import { CONFIG } from '../config/index.js';

const LOG_LEVELS = {
  DEBUG: { val: 0, color: '\x1b[38;5;244m' },
  INFO:  { val: 1, color: '\x1b[38;5;39m' },
  WARN:  { val: 2, color: '\x1b[38;5;214m' },
  ERROR: { val: 3, color: '\x1b[38;5;196m' }
};

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

export class Logger {
  static globalLevel = null;

  static setGlobalLevel(level) {
    if (typeof level === 'string' && LOG_LEVELS[level.toUpperCase()]) {
      Logger.globalLevel = level.toUpperCase();
    }
  }

  static getGlobalLevel() {
    if (Logger.globalLevel && LOG_LEVELS[Logger.globalLevel]) {
      return Logger.globalLevel;
    }
    const envLevel = (typeof process !== 'undefined' && process.env && process.env.LOG_LEVEL ? String(process.env.LOG_LEVEL) : '').toUpperCase();
    if (envLevel && LOG_LEVELS[envLevel]) {
      return envLevel;
    }
    const configLevel = (CONFIG && CONFIG.logLevel ? String(CONFIG.logLevel) : '').toUpperCase();
    if (configLevel && LOG_LEVELS[configLevel]) {
      return configLevel;
    }
    return 'DEBUG';
  }

  constructor(moduleName, minLevel = null, logFilePath = null) {
    this.moduleName = moduleName.toUpperCase();
    this._explicitLevel = minLevel && typeof minLevel === 'string' && LOG_LEVELS[minLevel.toUpperCase()]
      ? minLevel.toUpperCase()
      : null;
    this.logFilePath = logFilePath;
  }

  get minLevel() {
    return this._explicitLevel || Logger.getGlobalLevel();
  }

  set minLevel(level) {
    if (typeof level === 'string' && LOG_LEVELS[level.toUpperCase()]) {
      this._explicitLevel = level.toUpperCase();
    }
  }

  formatTimestamp() {
    const now = new Date();
    return now.toISOString().replace('T', ' ').slice(0, 19);
  }

  write(level, message, meta = null) {
    const levelKey = (level || '').toUpperCase();
    const minLevelKey = this.minLevel;

    const levelVal = LOG_LEVELS[levelKey]?.val ?? LOG_LEVELS.DEBUG.val;
    const minVal = LOG_LEVELS[minLevelKey]?.val ?? LOG_LEVELS.DEBUG.val;

    if (levelVal < minVal) return;

    const time = this.formatTimestamp();
    const color = LOG_LEVELS[levelKey]?.color || LOG_LEVELS.DEBUG.color;
    const metaStr = meta ? ` | ${typeof meta === 'object' ? JSON.stringify(meta) : meta}` : '';
    
    // Konsol formatı (Renkli)
    const consoleOutput = `${'\x1b[90m'}[${time}]${RESET} ${color}${BOLD}[${levelKey.padEnd(5)}]${RESET} ${'\x1b[35m'}[${this.moduleName}]${RESET} ${message}${metaStr}`;
    console.log(consoleOutput);

    // Dosyaya yazma (Opsiyonel / Renksiz)
    if (this.logFilePath) {
      const plainOutput = `[${time}] [${levelKey.padEnd(5)}] [${this.moduleName}] ${message}${metaStr}\n`;
      fs.appendFile(this.logFilePath, plainOutput, () => {});
    }
  }

  debug(msg, meta) { this.write('DEBUG', msg, meta); }
  info(msg, meta)  { this.write('INFO', msg, meta); }
  warn(msg, meta)  { this.write('WARN', msg, meta); }
  error(msg, meta) { this.write('ERROR', msg, meta); }
}
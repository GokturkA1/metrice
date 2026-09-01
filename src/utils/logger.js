import fs from 'node:fs';

const LOG_LEVELS = {
  DEBUG: { val: 0, color: '\x1b[38;5;244m' },
  INFO:  { val: 1, color: '\x1b[38;5;39m' },
  WARN:  { val: 2, color: '\x1b[38;5;214m' },
  ERROR: { val: 3, color: '\x1b[38;5;196m' }
};

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

export class Logger {
  constructor(moduleName, minLevel = 'DEBUG', logFilePath = null) {
    this.moduleName = moduleName.toUpperCase();
    this.minLevel = LOG_LEVELS[minLevel] ? minLevel : 'DEBUG';
    this.logFilePath = logFilePath;
  }

  formatTimestamp() {
    const now = new Date();
    return now.toISOString().replace('T', ' ').slice(0, 19);
  }

  write(level, message, meta = null) {
    if (LOG_LEVELS[level].val < LOG_LEVELS[this.minLevel].val) return;

    const time = this.formatTimestamp();
    const color = LOG_LEVELS[level].color;
    const metaStr = meta ? ` | ${typeof meta === 'object' ? JSON.stringify(meta) : meta}` : '';
    
    // Konsol formatı (Renkli)
    const consoleOutput = `${'\x1b[90m'}[${time}]${RESET} ${color}${BOLD}[${level.padEnd(5)}]${RESET} ${'\x1b[35m'}[${this.moduleName}]${RESET} ${message}${metaStr}`;
    console.log(consoleOutput);

    // Dosyaya yazma (Opsiyonel / Renksiz)
    if (this.logFilePath) {
      const plainOutput = `[${time}] [${level.padEnd(5)}] [${this.moduleName}] ${message}${metaStr}\n`;
      fs.appendFile(this.logFilePath, plainOutput, () => {});
    }
  }

  debug(msg, meta) { this.write('DEBUG', msg, meta); }
  info(msg, meta)  { this.write('INFO', msg, meta); }
  warn(msg, meta)  { this.write('WARN', msg, meta); }
  error(msg, meta) { this.write('ERROR', msg, meta); }
}
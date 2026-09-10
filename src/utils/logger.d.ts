export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

export class Logger {
  static globalLevel: LogLevel | null;
  static setGlobalLevel(level: string): void;
  static getGlobalLevel(): LogLevel;

  moduleName: string;
  logFilePath: string | null;
  minLevel: LogLevel;

  constructor(moduleName: string, minLevel?: string | null, logFilePath?: string | null);

  formatTimestamp(): string;
  write(level: LogLevel | string, message: string, meta?: any): void;
  debug(msg: string, meta?: any): void;
  info(msg: string, meta?: any): void;
  warn(msg: string, meta?: any): void;
  error(msg: string, meta?: any): void;
}

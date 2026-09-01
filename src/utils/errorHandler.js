import { Logger } from './logger.js';
import { I18n } from '../locales/i18n.js';

const log = new Logger('ERROR_HANDLER');

export class ErrorHandler {
  static initGlobalHandlers() {
    process.on('uncaughtException', (err) => {
      log.error(I18n.t('ERR_UNCAUGHT', { error: err.message }), { stack: err.stack });
    });

    process.on('unhandledRejection', (reason) => {
      log.error(I18n.t('ERR_UNHANDLED_REJECTION', { error: reason?.message || reason }));
    });
  }

  static safeJsonParse(str, fallback = null) {
    try {
      return JSON.parse(str);
    } catch {
      return fallback;
    }
  }

  static wrapAsync(fn, context = 'OPERATION') {
    return async (...args) => {
      try {
        return await fn(...args);
      } catch (err) {
        log.error(I18n.t('ERR_OPERATION_FAILED', { context, error: err.message }));
        return null;
      }
    };
  }
}
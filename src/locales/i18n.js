import { CONFIG } from '../config/index.js';
import tr from './tr.js';
import en from './en.js';

const dictionaries = { tr, en };
let currentLocale = (CONFIG && CONFIG.locale) || 'en';

export class I18n {
  static setLocale(locale) {
    if (dictionaries[locale]) {
      currentLocale = locale;
    }
  }

  static getLocale() {
    return currentLocale;
  }

  static t(key, params = {}) {
    const dict = dictionaries[currentLocale] || dictionaries.en || dictionaries.tr;
    let template = dict[key] || dictionaries.en?.[key] || dictionaries.tr?.[key] || key;

    for (const [paramKey, paramVal] of Object.entries(params)) {
      template = template.replaceAll(`{${paramKey}}`, String(paramVal));
    }

    return template;
  }
}
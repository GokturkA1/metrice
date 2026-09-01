import tr from './tr.js';

const dictionaries = { tr };
let currentLocale = 'tr';

export class I18n {
  static setLocale(locale) {
    if (dictionaries[locale]) {
      currentLocale = locale;
    }
  }

  static t(key, params = {}) {
    const dict = dictionaries[currentLocale] || dictionaries.tr;
    let template = dict[key] || key;

    for (const [paramKey, paramVal] of Object.entries(params)) {
      template = template.replaceAll(`{${paramKey}}`, String(paramVal));
    }

    return template;
  }
}
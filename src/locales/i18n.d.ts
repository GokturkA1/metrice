export type SupportedLocale = 'en' | 'tr';

export class I18n {
  static setLocale(locale: SupportedLocale | string): void;
  static getLocale(): string;
  static t(key: string, params?: Record<string, string | number>): string;
}

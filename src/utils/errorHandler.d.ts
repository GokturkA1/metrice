export class ErrorHandler {
  static initGlobalHandlers(): void;
  static safeJsonParse<T = any>(str: string, fallback?: T): T;
  static wrapAsync<T extends (...args: any[]) => Promise<any>>(
    fn: T,
    context?: string
  ): (...args: Parameters<T>) => Promise<ReturnType<T> | null>;
}

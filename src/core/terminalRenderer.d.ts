import type { TerminalSession } from './terminalSession.d.ts';

export class TerminalRenderer {
  session: TerminalSession;

  constructor(session: TerminalSession);

  static formatTime(isoString: string): string;
  static sanitizeContent(str: string): string;
  static wrapLineStrict(line: string, maxWidth: number): string[];

  formatMessagesToLines(messages: any[], maxLineWidth: number): string[];
  calculateInputRender(): { lineContent: string; cursorCol: number };
  renderInputOnly(): void;
  renderFull(messages?: any[]): void;
}

export interface AnsiCodes {
  CLEAR: string;
  CLEAR_LINE: string;
  RESET: string;
  BOLD: string;
  DIM: string;
  BG_DARK: string;
  BG_HEADER: string;
  BG_INPUT: string;
  FG_CYAN: string;
  FG_GREEN: string;
  FG_GRAY: string;
  FG_WHITE: string;
  FG_MAGENTA: string;
  FG_YELLOW: string;
  FG_RED: string;
  CURSOR_HIDE: string;
  CURSOR_SHOW: string;
  CURSOR_MOVE: (r: number, c: number) => string;
}

export const ANSI: AnsiCodes;

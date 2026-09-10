/* eslint-disable no-control-regex */
import { StringDecoder } from 'node:string_decoder';

export class InputParser {
  constructor() {
    this.decoder = new StringDecoder('utf8');
    this.escapeState = 0;
    this.escapeCode = '';
    this.isPasteMode = false;
    this.pasteBuffer = '';
  }

  extractTelnetEvents(buffer) {
    const cleanBytes = [];
    const events = [];

    for (let i = 0; i < buffer.length; i++) {
      if (buffer[i] === 0xFF) {
        // IAC SB NAWS (0xFF 0xFA 0x1F) -> Telnet Pencere Boyutu
        if (buffer[i + 1] === 0xFA && buffer[i + 2] === 0x1F) {
          const width = (buffer[i + 3] << 8) | buffer[i + 4];
          const height = (buffer[i + 5] << 8) | buffer[i + 6];
          if (width > 0 && height > 0) {
            events.push({ type: 'RESIZE', width, height });
          }

          i += 6;
          while (i < buffer.length && buffer[i] !== 0xF0) i++;
          continue;
        }

        if (buffer[i + 1] >= 0xFA && buffer[i + 1] <= 0xFE) {
          if (buffer[i + 1] === 0xFA) {
            i += 2;
            while (i < buffer.length && buffer[i] !== 0xF0) i++;
          } else {
            i += 2;
          }
          continue;
        }
        i += 1;
        continue;
      }
      cleanBytes.push(buffer[i]);
    }

    return { sanitizedBuffer: Buffer.from(cleanBytes), events };
  }

  parse(rawBuffer) {
    const { sanitizedBuffer, events } = this.extractTelnetEvents(rawBuffer);
    const actions = [...events];

    if (sanitizedBuffer.length === 0) return actions;

    let text = this.decoder.write(sanitizedBuffer);
    text = text.replace(/\r\x00/g, '\n').replace(/\r\n/g, '\n').replace(/\r/g, '\n');

    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      const code = char.charCodeAt(0);

      if (code === 0x00) continue;

      // ANSI Kaçış Dizisi Yakalama
      if (this.escapeState === 0 && code === 0x1B) {
        this.escapeState = 1;
        this.escapeCode = '\x1b';
        continue;
      } else if (this.escapeState === 1) {
        this.escapeCode += char;
        if (char === '[' || char === 'O') {
          this.escapeState = 2;
        } else {
          this.escapeState = 0;
          actions.push({ type: 'KEY_ESC' });
        }
        continue;
      } else if (this.escapeState === 2) {
        this.escapeCode += char;

        // ANSI Cursor Position Report (CPR): \x1b[<satır>;<sütun>R
        if (char === 'R') {
          const match = this.escapeCode.match(/\x1b\[(\d+);(\d+)R/);
          if (match) {
            const height = parseInt(match[1], 10);
            const width = parseInt(match[2], 10);
            if (width > 0 && height > 0) {
              actions.push({ type: 'RESIZE', width, height });
            }
          }
          this.escapeState = 0;
          this.escapeCode = '';
          continue;
        }

        // Bracketed Paste
        if (char === '~' || (code >= 0x40 && code <= 0x7E)) {
          if (this.escapeCode === '\x1b[200~') {
            this.isPasteMode = true;
            this.pasteBuffer = '';
          } else if (this.escapeCode === '\x1b[201~') {
            this.isPasteMode = false;
            actions.push({ type: 'PASTE_COMPLETE', content: this.pasteBuffer });
            this.pasteBuffer = '';
          } else {
            const action = this.mapEscapeSequence(this.escapeCode);
            if (action) actions.push(action);
          }
          this.escapeState = 0;
          this.escapeCode = '';
        }
        continue;
      }

      if (this.isPasteMode) {
        this.pasteBuffer += char;
        continue;
      }

      if (code === 0x09) {
        actions.push({ type: 'KEY_TAB' });
      } else if (code === 0x0A) {
        actions.push({ type: 'KEY_ENTER' });
      } else if (code === 0x08 || code === 0x7F) {
        actions.push({ type: 'KEY_BACKSPACE' });
      } else if (code === 0x17) {
        actions.push({ type: 'KEY_CTRL_W' });
      } else if (code === 0x15) {
        actions.push({ type: 'KEY_CTRL_U' });
      } else if (code === 0x03 || code === 0x04) {
        actions.push({ type: 'KEY_INTERRUPT' });
      } else if (code >= 32) {
        actions.push({ type: 'CHAR', char });
      }
    }

    return actions;
  }

  mapEscapeSequence(seq) {
    switch (seq) {
      case '\x1b[A':
      case '\x1bOA': return { type: 'KEY_UP' };
      case '\x1b[B':
      case '\x1bOB': return { type: 'KEY_DOWN' };
      case '\x1b[C':
      case '\x1bOC': return { type: 'KEY_RIGHT' };
      case '\x1b[D':
      case '\x1bOD': return { type: 'KEY_LEFT' };
      case '\x1b[H':
      case '\x1b[1~': return { type: 'KEY_HOME' };
      case '\x1b[F':
      case '\x1b[4~': return { type: 'KEY_END' };
      case '\x1b[3~': return { type: 'KEY_DELETE' };
      case '\x1b[5~': return { type: 'KEY_PAGE_UP' };
      case '\x1b[6~': return { type: 'KEY_PAGE_DOWN' };
      default:
        return { type: 'KEY_UNKNOWN', raw: seq };
    }
  }
}
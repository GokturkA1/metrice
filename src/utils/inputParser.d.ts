/// <reference types="node" />
import { StringDecoder } from 'node:string_decoder';

export interface InputAction {
  type: string;
  char?: string;
  width?: number;
  height?: number;
  text?: string;
}

export interface ExtractedTelnetEvents {
  sanitizedBuffer: Buffer;
  events: InputAction[];
}

export class InputParser {
  decoder: StringDecoder;
  escapeState: number;
  escapeCode: string;
  isPasteMode: boolean;
  pasteBuffer: string;

  constructor();

  extractTelnetEvents(buffer: Buffer): ExtractedTelnetEvents;
  parse(rawBuffer: Buffer): InputAction[];
}

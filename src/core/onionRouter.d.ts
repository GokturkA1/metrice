/// <reference types="node" />
import { EventEmitter } from 'node:events';
import { OnionCellPacket, ProtocolPacket } from '../types/protocol.d.ts';

export const UNIFORM_CELL_SIZE: number;
export const MAX_ONION_PAYLOAD: number;

export interface CircuitHop {
  address: string;
  kemPublicKey: string;
  nodeId: string;
}

export interface ClientCircuit {
  circuitId: string;
  hops: CircuitHop[];
  keys: Buffer[];
  targetNodeId: string | null;
  createdAt: number;
}

export interface OnionRouterOptions {
  federation: any;
  db: any;
  myIdentity: any;
  rendezvousTunnels: any;
}

export class OnionRouter extends EventEmitter {
  federation: any;
  db: any;
  myIdentity: any;
  rendezvousTunnels: any;
  clientCircuits: Map<string, ClientCircuit>;
  circuitTtl: number;

  constructor(options: OnionRouterOptions);

  static getPaddedCellObject(cell: OnionCellPacket): OnionCellPacket;
  static formatPaddedCell(cell: OnionCellPacket): string;
  static getHopIdentifier(channel: any): string;

  buildCircuit(hops: CircuitHop[], targetNodeId?: string | null): Promise<ClientCircuit>;
  sendOnionData(circuit: ClientCircuit, messagePacket: ProtocolPacket | object): Promise<boolean>;
  handleCircuitCreate(channel: any, packet: any): Promise<void>;
  handleCircuitExtend(channel: any, packet: any): Promise<void>;
  handleOnionCell(channel: any, packet: OnionCellPacket): Promise<void>;
  handleCircuitDestroy(channel: any, packet: any): Promise<void>;
  destroyCircuit(circuitId: string): Promise<void>;
  close(): void;
}

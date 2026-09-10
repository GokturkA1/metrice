export interface CommandContext {
  args: string[];
  argStr: string;
  session: any;
  db: any;
  federation?: any;
  clientServer?: any;
  userAddress: string;
}

export interface CommandModule {
  name: string;
  aliases?: string[];
  description?: string;
  usage?: string;
  execute: (context: CommandContext) => void | Promise<void>;
}

export class CommandRegistry {
  commands: Map<string, CommandModule>;

  constructor();

  register(commandModule: CommandModule): void;
  get(commandName: string): CommandModule | undefined;
  getAllUnique(): CommandModule[];
  execute(input: string, context: { session: any; db: any; federation?: any; userAddress: string; clientServer?: any }): Promise<boolean>;
}

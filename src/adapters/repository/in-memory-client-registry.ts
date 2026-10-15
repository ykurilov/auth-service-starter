import {
  applyClientPatch,
  type Client,
  type ClientPatch,
  type ClientWriteStore,
} from '../../domain/clients/client.js';

export class InMemoryClientRegistry implements ClientWriteStore {
  private readonly byId = new Map<string, Client>();

  constructor(clients: Client[] = []) {
    for (const c of clients) this.byId.set(c.id, InMemoryClientRegistry.copy(c));
  }

  async findClient(id: string): Promise<Client | null> {
    const c = this.byId.get(id);
    return c ? InMemoryClientRegistry.copy(c) : null;
  }

  async list(): Promise<Client[]> {
    return [...this.byId.values()].map((c) => InMemoryClientRegistry.copy(c));
  }

  async create(client: Client): Promise<void> {
    if (this.byId.has(client.id)) {
      throw new Error(`client already exists: ${client.id}`);
    }
    this.byId.set(client.id, InMemoryClientRegistry.copy(client));
  }

  async update(id: string, patch: ClientPatch): Promise<void> {
    const existing = this.byId.get(id);
    if (!existing) throw new Error(`client not found: ${id}`);
    this.byId.set(id, InMemoryClientRegistry.copy(applyClientPatch(existing, patch)));
  }

  async delete(id: string): Promise<void> {
    this.byId.delete(id);
  }

  // Копия с новыми массивами: списки не должны утекать по ссылке ни при чтении,
  // ни при записи (мутация аргумента create/update не портит хранилище).
  private static copy(c: Client): Client {
    const copy: Client = {
      ...c,
      redirectUris: [...c.redirectUris],
      allowedProviders: [...c.allowedProviders],
    };
    if (c.postLogoutRedirectUris !== undefined) {
      copy.postLogoutRedirectUris = [...c.postLogoutRedirectUris];
    }
    return copy;
  }
}

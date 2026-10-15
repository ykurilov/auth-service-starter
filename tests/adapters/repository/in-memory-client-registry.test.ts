import { describe, it, expect } from 'vitest';
import { InMemoryClientRegistry } from '../../../src/adapters/repository/in-memory-client-registry.js';
import type { Client } from '../../../src/domain/clients/client.js';

const client: Client = {
  id: 'app1',
  type: 'external',
  redirectUris: ['https://app1.example/callback'],
  allowedProviders: ['email'],
};

describe('InMemoryClientRegistry', () => {
  it('находит клиента по id', async () => {
    const reg = new InMemoryClientRegistry([client]);
    expect((await reg.findClient('app1'))?.type).toBe('external');
  });

  it('возвращает null для неизвестного id', async () => {
    const reg = new InMemoryClientRegistry([client]);
    expect(await reg.findClient('нет')).toBeNull();
  });

  it('возвращает копию: мутация результата не портит реестр', async () => {
    const reg = new InMemoryClientRegistry([client]);
    const found = await reg.findClient('app1');
    found?.redirectUris.push('https://evil.example');
    found?.allowedProviders.push('google');
    const again = await reg.findClient('app1');
    expect(again?.redirectUris).toEqual(['https://app1.example/callback']);
    expect(again?.allowedProviders).toEqual(['email']);
  });

  it('CRUD round-trip: create + list + findClient + update + delete', async () => {
    const reg = new InMemoryClientRegistry();
    await reg.create(client);
    expect(await reg.list()).toHaveLength(1);
    expect((await reg.findClient('app1'))?.type).toBe('external');

    await reg.update('app1', { redirectUris: ['https://app1.example/new'] });
    expect((await reg.findClient('app1'))?.redirectUris).toEqual([
      'https://app1.example/new',
    ]);

    await reg.delete('app1');
    expect(await reg.findClient('app1')).toBeNull();
    expect(await reg.list()).toHaveLength(0);
  });

  it('create дубликата id бросает', async () => {
    const reg = new InMemoryClientRegistry([client]);
    await expect(reg.create(client)).rejects.toThrow();
  });

  it('update отсутствующего id бросает', async () => {
    const reg = new InMemoryClientRegistry();
    await expect(reg.update('нет', { type: 'internal' })).rejects.toThrow();
  });

  it('list отдаёт копии: мутация не портит реестр', async () => {
    const reg = new InMemoryClientRegistry([client]);
    const listed = (await reg.list())[0]!;
    listed.redirectUris.push('https://evil.example');
    const again = await reg.list();
    expect(again[0]!.redirectUris).toEqual(['https://app1.example/callback']);
  });

  it('create не хранит ссылку на аргумент', async () => {
    const reg = new InMemoryClientRegistry();
    const arg: Client = {
      id: 'app2',
      type: 'internal',
      redirectUris: ['https://app2.example/cb'],
      allowedProviders: ['email'],
    };
    await reg.create(arg);
    arg.redirectUris.push('https://evil.example');
    expect((await reg.findClient('app2'))?.redirectUris).toEqual([
      'https://app2.example/cb',
    ]);
  });
});

import { it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { MAX_BINDINGS_PER_CHAIN, type BrowserBinding, type SsoSessionStore } from '../../../src/domain/sso/sso-session.js';

const T0 = new Date('2026-07-01T00:00:00Z').getTime();
const at = (minutes: number) => new Date(T0 + minutes * 60_000);

function binding(chainId: string, minutes: number): BrowserBinding {
  return { chainId, tokenHash: `b-${randomUUID()}`, createdAt: at(minutes), expiresAt: at(minutes + 1000) };
}

// Привязки браузеров: общий контракт хранилищ SsoSessionStore. make — пустое
// хранилище для теста.
export function bindingContract(make: () => SsoSessionStore): void {
  it('привязки: у цепочки несколько, каждая со своим сроком; deleteChainBindings удаляет только её', async () => {
    const s = make();
    const chain = randomUUID();
    const other = randomUUID();
    const a = binding(chain, 0);
    const b = binding(chain, 1);
    const c = binding(other, 2);
    for (const x of [a, b, c]) await s.addBinding(x);
    expect(await s.findBinding(a.tokenHash)).toEqual(a);
    expect(await s.findBinding(b.tokenHash)).toEqual(b);
    expect(await s.browserDeadline(chain)).toEqual(b.expiresAt);
    expect(await s.renewBinding(a.tokenHash, at(5000))).toBe(true);
    expect(await s.browserDeadline(chain)).toEqual(at(5000));
    await s.deleteBinding(b.tokenHash);
    expect(await s.findBinding(b.tokenHash)).toBeNull();
    expect(await s.renewBinding(b.tokenHash, at(6000))).toBe(false);
    await s.deleteChainBindings(chain);
    expect(await s.findBinding(a.tokenHash)).toBeNull();
    expect(await s.browserDeadline(chain)).toBeNull();
    expect(await s.findBinding(c.tokenHash)).toEqual(c);
  });

  it(`привязки: у цепочки не больше ${MAX_BINDINGS_PER_CHAIN}, уходят самые давние по сроку`, async () => {
    const s = make();
    const chain = randomUUID();
    const all: BrowserBinding[] = [];
    for (let i = 0; i < MAX_BINDINGS_PER_CHAIN + 3; i++) {
      all.push(binding(chain, i));
      await s.addBinding(all[i]!);
    }
    const kept = await Promise.all(all.map((x) => s.findBinding(x.tokenHash)));
    expect(kept.filter(Boolean)).toHaveLength(MAX_BINDINGS_PER_CHAIN);
    expect(kept.slice(0, 3).every((x) => x === null)).toBe(true);
  });

  it('привязки: deleteExpired удаляет истёкшие до before и не трогает действующие', async () => {
    const s = make();
    const chain = randomUUID();
    const old = binding(chain, 0);
    const live = binding(chain, 5000);
    await s.addBinding(old);
    await s.addBinding(live);
    expect(await s.deleteExpired(at(3000))).toBe(1);
    expect(await s.findBinding(old.tokenHash)).toBeNull();
    expect(await s.findBinding(live.tokenHash)).toEqual(live);
  });
}

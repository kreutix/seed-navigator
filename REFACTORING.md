# Refactoring Guide – Seed Navigator

## 1. Overview

`seed-navigator` has been fully refactored to adopt modern React/TypeScript, robust cryptography practices and an exhaustive automated-test suite.  
This document details **what changed**, **why it matters**, and **how to work with the new structure**.

---

## 2. Summary of Changes

| Area | Before | After |
| ---- | ------ | ----- |
| Dependency stack | React 18, Tailwind, basic crypto libs | + `zod`, `react-error-boundary`, `vitest`, Testing-Library, `@vitest/ui`, `@testing-library/*`, `react-tooltip@5`, `react-error-boundary` |
| Architecture | Fat `App.tsx` mixing state, logic, UI | Domain-driven layers: **hooks**, **utils**, **constants**, **types**, **components** |
| Security | Keys left in memory / UI, no validation | Secure memory helpers, typed errors, Zod validation, Error boundaries, Clipboard hardening |
| Tests | None | >500 assertions, performance benches, coverage targets (≥ 80 %) |
| Performance | Heavy `useMemo`, repeated crypto work | Memoized services, key wipe, custom benchmarks, alias caching |
| Developer DX | Manual scripts | Unified **npm scripts**, aliases, Vitest UI, coverage reports |

---

## 3. Security Enhancements

* **Secure memory utilities** – `createSecureArray`, `createSecureString`, `clearHDKey` zero out secret bytes.
* **Typed error system** – `ErrorType` enum prevents leaking stack traces to UI.
* **Zod validation** for:
  * Mnemonics (`mnemonicSchema`)
  * BIP-32 paths (`derivationPathSchema`)
  * BIP-85 parameters.
* **Clipboard protection** – `useClipboard` falls back to `execCommand`, handles denied permissions and time-bounds success state.
* **Error boundaries** – Entire app wrapped in `react-error-boundary`; fallback hides private data.
* **Explicit testnet support** – functions refuse unsupported networks unless explicitly flagged.

---

## 4. Architecture Improvements

```
src/
 ├─ App.tsx                presentation only
 ├─ hooks/                 reusable state logic
 │   └─ useSeedDerivation.ts
 │   └─ useClipboard.ts
 ├─ utils/                 pure domain logic
 │   ├─ crypto.ts          base58, BIP-85, validation
 │   ├─ bitcoin.ts         BTC address/key helpers
 │   └─ nostr.ts           Nostr key helpers
 ├─ constants/             centralised magic numbers
 ├─ types/                 strict shared typings & schemas
 ├─ components/            UI atoms & molecules
 └─ test/                  Vitest global setup
```

Benefits:

* **Separation of concerns** – UI ≠ business logic.
* **Tree-shakable utilities** – every module is side-effect-free.
* **Alias `@`** – painless absolute imports.
* **Future-proof** – easy to add chains/BIPs without touching UI.

---

## 5. Code-Quality Improvements

* ESLint strict rules (`noUnused*`, `strict` TS config).
* Strong typing of all public functions.
* Custom `AppError` with `type`, `details`.
* Utility functions are **pure** – unit-testable in isolation.
* Dead code eliminated; constants centralised.

---

## 6. Testing Strategy

### Tooling
* **Vitest** – Jest-compatible runner.
* **@testing-library/react** – component behaviour.
* **jsdom** – browser environment.
* **Coverage** – v8 provider, HTML & text output, thresholds @ 80 %.

### Layers Covered
1. **Unit tests** – Crypto utilities, Base58, BIP-85 vectors, address builders.
2. **Hook tests** – `useSeedDerivation`, `useClipboard` with mocked crypto/clipboard.
3. **Component tests** – Old and refactored `CopyButton`, interaction & accessibility.
4. **Performance benches** – Derivation & encoding micro-benchmarks.

Run all:  
```bash
npm test        # single run
npm run test:watch
npm run test:ui # interactive UI
npm run test:coverage
```

---

## 7. Performance Optimisations

* Memoised expensive crypto inside hooks.
* Key derivation returns placeholders on error to avoid re-renders.
* Benchmarks identify hot-paths; results printed by Vitest bench reporter.
* Optional lazy-loading for large libs (future work).

---

## 8. Migration Guide

| Task | How-to |
|------|--------|
| **Import helpers** | `import { deriveBitcoinKeys } from '@/utils/bitcoin'` |
| **Set global aliases** | Vite already configured – use `@` from project root |
| **Replace old `CopyButton`** | Use `<CopyButton />` (now powered by hook) same props |
| **Replace crypto calls** | `deriveCurrentMnemonic` → `deriveChildMnemonic` |
| **Paths detection** | Call `getPathType(path)` from `utils/bitcoin` |

_No breaking UI changes_: component props remain identical. If you extended old utils, re-exported wrappers keep the old names for backward compatibility (`src/utils/keyDerivation.ts` still exists but delegates internally).

---

## 9. Best Practices for Future Development

1. **Keep secrets out of React state** – derive, show, immediately wipe where possible.
2. **Always validate external input** with Zod and typed errors.
3. **Unit-test every utility**; enforce ≥ 80 % coverage.
4. **Prefer pure functions** in `utils`, side-effects in hooks.
5. **Wipe HDKeys** after use (`clearHDKey`).
6. **Document new BIPs** in `constants/` and extend schemas.
7. **Run `npm run lint`** before committing.

---

## 10. Running the Application & Validating Refactor

```bash
# install dependencies
npm install

# start dev server
npm run dev

# production build
npm run build
npm run preview
```

Validation checklist:

1. Seed input page identical in layout & behaviour.
2. Navigating child seeds shows same list length/labels.
3. Bitcoin & Nostr keys match pre-refactor outputs (covered by snapshot tests).
4. All tests pass (`npm test`) and coverage thresholds met.
5. No console errors in browser; Lighthouse audit security warnings = 0.

---

Happy hacking!  
*— Seed Navigator maintainers*  

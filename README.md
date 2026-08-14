# Crossdyne.Security (TypeScript)

> Cross-platform cryptographic library — [.NET](https://github.com/crossdyne/dotnet-security) | [TypeScript](https://github.com/crossdyne/typescript-security)
>
> [English](#english) | [Русский](#русский)

---

<a name="english"></a>
## English

TypeScript / JavaScript implementation of the Crossdyne.Security cryptographic library via the native **Web Crypto API**.

## Installation

```bash
npm install @crossdyne/security
```

### Features

- **AES-256-GCM** — authenticated symmetric encryption via `crypto.subtle`
- **PBKDF2 + HKDF** — secure key derivation from passwords
- **SRP-6a** — password-authenticated key exchange without sending the password to the server
- **Zero-memory** — sensitive buffers are explicitly overwritten after use
- **No custom crypto primitives** — relies entirely on the browser / Node.js Web Crypto API
- **Cross-platform** — compatible with the [.NET implementation](https://github.com/crossdyne/dotnet-security). Encrypted payloads and SRP messages are interchangeable between TS and .NET.

### Requirements

- TypeScript 5.3+
- Web Crypto API (`crypto.subtle`) — modern browsers and Node.js 18+

### Project Structure

```
crossdyne-security/
├── crypto/
│   ├── crypto-service.ts              # AES-GCM encrypt / decrypt
│   ├── key-derivation-service.ts      # Derive KEK and AuthHash (PBKDF2 → HKDF)
│   ├── crypto-profile-registry.ts     # Versioned crypto profiles
│   ├── crypto-version.ts              # Enum: V1, V2, ...
│   └── kdf-options.ts                 # PBKDF2 / HKDF parameters
├── srp/
│   ├── srp-server-service.ts          # SRP server (challenge, verify)
│   ├── srp-client-service.ts          # SRP client (proof, verifier)
│   ├── srp-key-derivation-service.ts  # Derive auth-hash for SRP
│   ├── srp-context-factory.ts         # Creates SRP context (N, g, k, hash)
│   ├── srp-group.ts                   # Enum: Group2048, Group4096, ...
│   └── srp-encoding.ts                # BigInt ↔ bytes helpers
└── utils/
    ├── security-utils.ts              # Base64, BigInt, fixed-time compare
    └── srp-encoding.ts               # Hash moduli, session key, M1 / M2
```

### Quick Start

#### Encrypt / Decrypt

```typescript
import { CryptoService } from './crypto/crypto-service.js';
import { CryptoVersion } from './crypto/crypto-version.js';

const crypto = new CryptoService();
const key = crypto.generateRandomBytes(32); // AES-256

const encrypted = await crypto.encryptData(
  { message: "Hello, World!" },
  key,
  CryptoVersion.V1
);

const decrypted = await crypto.decryptData<MyData>(encrypted, key);
```

Encrypted payload format (Base64):

```
[Version (1 byte)][Nonce (N bytes)][Ciphertext + Tag]
```

#### Key Derivation from Password

```typescript
import { KeyDerivationService } from './crypto/key-derivation-service.js';
import { CryptoVersion } from './crypto/crypto-version.js';

const kdf = new KeyDerivationService();
const salt = crypto.getRandomValues(new Uint8Array(16));

const { kek, authHash } = await kdf.deriveKeysFromPassword(
  "user@example.com",
  "SuperSecret123!",
  salt,
  CryptoVersion.V1
);
```

- `kek` — `Uint8Array` key for AES-GCM
- `authHash` — Base64 string for SRP authentication

#### SRP Authentication Flow

**Server — generate challenge**

```typescript
import { SrpServerService } from './srp/srp-server-service.js';
import { SrpGroup } from './srp/srp-group.js';

const server = new SrpServerService();

const session = await server.getSrpChallenge(
  "user@example.com",
  verifierBytes,
  salt,
  SrpGroup.Group2048
);

// Send to client: salt + session.publicKeyB (B)
```

**Client — generate proof**

```typescript
import { SrpClientService } from './srp/srp-client-service.js';
import { SrpKeyDerivationService } from './srp/srp-key-derivation-service.js';
import { SrpGroup } from './srp/srp-group.js';
import { CryptoVersion } from './crypto/crypto-version.js';

const client = new SrpClientService();
const kdf = new SrpKeyDerivationService();

// 1. Derive auth-hash from password
const authHash = await kdf.deriveAuthHashForSrp(
  identity, password, salt, SrpGroup.Group2048, CryptoVersion.V1
);

// 2. Generate proof
const { A, M1, SessionKeyK } = await client.generateSrpProof(
  identity,
  authHash,
  btoa(String.fromCharCode(...salt)),
  btoa(String.fromCharCode(...session.publicKeyB)),
  SrpGroup.Group2048
);

// Send to server: A + M1
```

**Server — verify proof**

```typescript
const serverM2 = await server.verifySrpProof(
  session,
  A,
  M1,
  SrpGroup.Group2048
);

// Send to client: serverM2
```

**Client — verify server proof**

```typescript
const isValid = await client.verifyServerM2(
  A,
  M1,
  SessionKeyK,
  serverM2,
  SrpGroup.Group2048
);
```

### Security Notes

- All sensitive buffers are explicitly overwritten after use
- Salt must be **at least 16 bytes**
- AES-256 key must be **exactly 32 bytes**
- SRP groups are protected against small-subgroup attacks (checks `A % N != 0`, `B != 0`)
- Relies entirely on the native Web Crypto API — no custom crypto primitives

### License

MIT

---

<a name="русский"></a>
## Русский

Реализация криптографической библиотеки Crossdyne.Security для TypeScript / JavaScript через нативный **Web Crypto API**.

## Установка

```bash
npm install @crossdyne/security
```

### Возможности

- **AES-256-GCM** — симметричное шифрование с аутентификацией через `crypto.subtle`
- **PBKDF2 + HKDF** — надёжный вывод ключей из пароля
- **SRP-6a** — протокол аутентификации без передачи пароля на сервер
- **Zero-memory** — чувствительные буферы явно перезаписываются после использования
- **Никаких самописных криптопримитивов** — только нативный Web Crypto API браузера / Node.js
- **Кроссплатформенность** — совместима с [.NET-реализацией](https://github.com/crossdyne/dotnet-security). Зашифрованные данные и SRP-сообщения взаимозаменяемы между TS и .NET.

### Требования

- TypeScript 5.3+
- Web Crypto API (`crypto.subtle`) — современные браузеры и Node.js 18+

### Структура проекта

```
crossdyne-security/
├── crypto/
│   ├── crypto-service.ts              # AES-GCM шифрование / дешифрование
│   ├── key-derivation-service.ts      # Вывод KEK и AuthHash (PBKDF2 → HKDF)
│   ├── crypto-profile-registry.ts     # Версионированные криптопрофили
│   ├── crypto-version.ts              # Enum: V1, V2, ...
│   └── kdf-options.ts                 # Параметры PBKDF2 / HKDF
├── srp/
│   ├── srp-server-service.ts          # SRP сервер (challenge, проверка)
│   ├── srp-client-service.ts          # SRP клиент (proof, верификатор)
│   ├── srp-key-derivation-service.ts  # Вывод auth-hash для SRP
│   ├── srp-context-factory.ts         # Создание SRP-контекста (N, g, k, hash)
│   ├── srp-group.ts                   # Enum: Group2048, Group4096, ...
│   └── srp-encoding.ts                # BigInt ↔ bytes хелперы
└── utils/
    ├── security-utils.ts              # Base64, BigInt, сравнение в постоянное время
    └── srp-encoding.ts               # Хеш модулей, сессионный ключ, M1 / M2
```

### Быстрый старт

#### Шифрование / дешифрование

```typescript
import { CryptoService } from './crypto/crypto-service.js';
import { CryptoVersion } from './crypto/crypto-version.js';

const crypto = new CryptoService();
const key = crypto.generateRandomBytes(32); // AES-256

const encrypted = await crypto.encryptData(
  { message: "Hello, World!" },
  key,
  CryptoVersion.V1
);

const decrypted = await crypto.decryptData<MyData>(encrypted, key);
```

Формат зашифрованных данных (Base64):

```
[Version (1 byte)][Nonce (N bytes)][Ciphertext + Tag]
```

#### Вывод ключей из пароля

```typescript
import { KeyDerivationService } from './crypto/key-derivation-service.js';
import { CryptoVersion } from './crypto/crypto-version.js';

const kdf = new KeyDerivationService();
const salt = crypto.getRandomValues(new Uint8Array(16));

const { kek, authHash } = await kdf.deriveKeysFromPassword(
  "user@example.com",
  "SuperSecret123!",
  salt,
  CryptoVersion.V1
);
```

- `kek` — `Uint8Array` ключ для AES-GCM
- `authHash` — Base64-строка для SRP-аутентификации

#### SRP-аутентификация

**Сервер — генерация challenge**

```typescript
import { SrpServerService } from './srp/srp-server-service.js';
import { SrpGroup } from './srp/srp-group.js';

const server = new SrpServerService();

const session = await server.getSrpChallenge(
  "user@example.com",
  verifierBytes,
  salt,
  SrpGroup.Group2048
);

// Отправить клиенту: salt + session.publicKeyB (B)
```

**Клиент — генерация proof**

```typescript
import { SrpClientService } from './srp/srp-client-service.js';
import { SrpKeyDerivationService } from './srp/srp-key-derivation-service.js';
import { SrpGroup } from './srp/srp-group.js';
import { CryptoVersion } from './crypto/crypto-version.js';

const client = new SrpClientService();
const kdf = new SrpKeyDerivationService();

// 1. Вывести auth-hash из пароля
const authHash = await kdf.deriveAuthHashForSrp(
  identity, password, salt, SrpGroup.Group2048, CryptoVersion.V1
);

// 2. Сгенерировать proof
const { A, M1, SessionKeyK } = await client.generateSrpProof(
  identity,
  authHash,
  btoa(String.fromCharCode(...salt)),
  btoa(String.fromCharCode(...session.publicKeyB)),
  SrpGroup.Group2048
);

// Отправить серверу: A + M1
```

**Сервер — проверка proof**

```typescript
const serverM2 = await server.verifySrpProof(
  session,
  A,
  M1,
  SrpGroup.Group2048
);

// Отправить клиенту: serverM2
```

**Клиент — проверка server proof**

```typescript
const isValid = await client.verifyServerM2(
  A,
  M1,
  SessionKeyK,
  serverM2,
  SrpGroup.Group2048
);
```

### Безопасность

- Все чувствительные буферы явно перезаписываются после использования
- Соль должна быть **минимум 16 байт**
- Ключ AES-256 — **строго 32 байта**
- SRP-группы защищены от атак на малые подгруппы (проверки `A % N != 0`, `B != 0`)
- Полностью опирается на нативный Web Crypto API — никаких самописных криптопримитивов

### Лицензия

MIT

# Fleetcore

**Server-side reference for a self-hosted [Amnezia](https://amnezia.org) fleet — serves a signed, health-selected config so clients can fail over across your own servers.**

[English](#english) · [Русский](#русский)

> 🚧 **Status:** design complete ([DESIGN.md](DESIGN.md)); M1 implementation in progress. Clean-room, MIT.

---

## English

### What it is

Self-hosting a VPN is great until a single server has a bad day — the host, a block, or a crash.
So self-hosters usually run a small **fleet**, but the app only understands **static** configs:
when a server dies you switch configs by hand. There is no failover across your own
infrastructure.

Fleetcore is a tiny control-plane you run next to your own servers. Clients that imported a
Fleetcore-issued config periodically ask it for the **current best config** and apply it
automatically — giving you in-app **failover / rotation** across your fleet.

It is the **server side** of a proposed, additive Amnezia-client feature (let a self-hosted
config carry its own key-pinned update endpoint). Fleetcore implements and pins down the exact
wire format so a client can interoperate.

### How it works

- The client polls `GET /v1/config`.
- Fleetcore health-checks the fleet, picks the current best server, and returns its config,
  **Ed25519-signed**.
- The client verifies the signature against a **public key pinned at import time** and applies
  the config.

Integrity comes from the signature, not the transport — a config cannot be forged even over
plain HTTP. Fleetcore never proxies VPN traffic; it only says *which* of your servers to use.

### Design & spec

The full, self-contained spec — wire protocol, the exact client decode contract, wire-key
reference, a complete example payload, and the crypto spec — is in **[DESIGN.md](DESIGN.md)**.

### Planned usage

```sh
fleetcore keygen -o keys/ed25519.key      # generate signing key; prints the pinned pubkey
fleetcore serve  -c fleet.yaml            # run the control-plane
```

```sh
docker run --rm -p 8443:8443 \
  -v $PWD/fleet.yaml:/etc/fleetcore/fleet.yaml:ro \
  -v $PWD/fleet:/fleet:ro -v $PWD/keys:/keys:ro \
  ghcr.io/<you>/fleetcore:latest serve -c /etc/fleetcore/fleet.yaml
```

### Non-goals & safety

- Not a replacement for anything; purely additive and opt-in.
- Does **not** proxy or touch VPN traffic — serves only config metadata.
- No dependency on any vendor's gateway or relay; clients talk to Fleetcore directly.
- Clean-room: no third-party client code, no secrets in the repo.

### License

MIT.

---

## Русский

**Серверный референс для self-hosted [Amnezia](https://amnezia.org)-флота — отдаёт
подписанный, health-selected конфиг, чтобы клиенты переключались между твоими серверами при
сбоях.**

### Что это

Self-hosting VPN — отлично, пока один сервер не подведёт: хостер, блокировка, падение. Поэтому
серверов обычно держишь несколько — небольшой **флот**, но приложение умеет только
**статичные** конфиги: сервер лёг — переключаешь конфиг руками. Failover'а по своей
инфраструктуре нет.

Fleetcore — крошечный control-plane, который ты гоняешь рядом со своими серверами. Клиенты с
импортированным Fleetcore-конфигом периодически спрашивают у него **текущий лучший конфиг** и
применяют его автоматически — это in-app **failover / ротация** по флоту.

Это **серверная сторона** предлагаемой additive-фичи клиента Amnezia (разрешить self-hosted
конфигу нести свой key-pinned update-эндпоинт). Fleetcore реализует и фиксирует точный
wire-формат для интеропа.

### Как это работает

- Клиент опрашивает `GET /v1/config`.
- Fleetcore проверяет здоровье флота, выбирает текущий лучший сервер и отдаёт его конфиг,
  **подписанный Ed25519**.
- Клиент проверяет подпись по **публичному ключу, запиненному при импорте**, и применяет
  конфиг.

Целостность даёт подпись, а не транспорт — подделать конфиг нельзя даже по обычному HTTP.
Fleetcore не проксирует VPN-трафик; он лишь говорит, *какой* из твоих серверов использовать.

### Дизайн и спека

Полная самодостаточная спека — wire-протокол, точный контракт декода клиента, таблица
wire-ключей, полный пример payload и крипто-спека — в **[DESIGN.md](DESIGN.md)**.

### Планируемое использование

Команды и Docker-запуск — см. [Planned usage](#planned-usage) выше (интерфейс языконезависим).

### Non-goals и безопасность

- Не замена чему-либо; чистое additive-дополнение, opt-in.
- **Не** проксирует и не трогает VPN-трафик — только метаданные конфига.
- Не зависит от чьего-либо gateway/реле; клиенты общаются с Fleetcore напрямую.
- Clean-room: без чужого клиентского кода и секретов в репо.

### Лицензия

MIT.

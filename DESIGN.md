# fleetcore — design

> Reference control-plane for a **self-hosted VPN fleet**. Clean-room, Go, single small container.
> Repo name `fleetcore` is a placeholder — rename freely.
>
> **This document is self-contained.** Everything needed to build the server (the exact
> client-side decode contract, wire keys, a full example payload, and the crypto spec) is
> inlined in §5 and the Appendices. You do **not** need access to any other repository, the
> Amnezia client source, or any operator-internal system to implement M1. All client-side
> facts were extracted and adversarially verified against
> **`amnezia-vpn/amnezia-client`** — the decode logic against tag **`4.8.19.0`**
> (`client/ui/controllers/api/apiConfigsController.cpp`), and the constant wire strings against
> tag `4.8.15.4` (`client/protocols/protocols_defs.h`, `client/containers/containers_defs.cpp`
> — these literals are stable across versions). See Appendix F for permalinks.

## 1. What this is

An operator (a self-hoster) runs one `fleetcore` container next to their own VPN servers.
VPN clients that imported a fleetcore-issued config periodically ask fleetcore for the
**current best config** and apply it automatically. This gives self-hosters in-app
**failover / rotation** across their own servers, instead of hand-switching static configs
when a server dies.

fleetcore is the **server side** of the proposal in the Amnezia issue
*"Self-hosted: optional per-config update endpoint for in-app fleet failover/rotation"*
(amnezia-vpn/amnezia-client#TBD). It implements and pins down the exact wire format so a
client (Amnezia, or anything else) can interoperate. Attach it to the issue as a runnable
companion so maintainers can `docker run` the whole loop.

**Clean-room, on purpose:** no third-party client code, no secrets, no dependency on any
product's gateway or relay. It never phones any external infrastructure. MIT.

## 2. Non-goals

- Not a replacement for anything. Purely additive, opt-in.
- No premium / billing / accounts.
- **Does not proxy or touch VPN traffic.** It serves only *config metadata* (which server to
  use), signed. The data plane is the operator's own servers.
- Not tied to any vendor's infrastructure. It is polled **directly** by clients; it never
  talks to a gateway.

## 3. Actors

| Actor | Role |
|---|---|
| **Operator** | The self-hoster. Runs fleetcore + N VPN servers. Holds the signing private key. |
| **fleetcore** | This service. Knows the fleet, checks health, selects the best server, returns a signed config. |
| **Client** | The VPN app. Imported a config carrying (a) the fleetcore endpoint URL and (b) fleetcore's pinned public key. Polls, verifies signature, applies. |

## 4. Trust model

- Trust is anchored by a **public key pinned in the client config at import time**
  (trust-on-first-import). The client accepts an updated config **only** if it is signed by
  that key.
- Because integrity is guaranteed by the signature over the payload, transport may be plain
  HTTP or HTTPS — a MITM cannot forge a config without the private key. HTTPS still
  recommended for privacy.
- fleetcore serves only configs for servers the operator owns. A client can never be pointed
  anywhere except by a payload the operator's key signed.
- The private key lives **only** on the operator's fleetcore host (mounted volume / secret),
  never baked into the image or committed to the repo.

## 5. Wire protocol

### 5.1 Endpoints

| Method / path | Purpose |
|---|---|
| `GET /v1/config` | Current best config, signed. The client polls this. |
| `GET /v1/pubkey` | Ed25519 public key (`ed25519:<base64>`), for embedding when issuing a client config. |
| `GET /healthz` | fleetcore's own liveness, for the operator's monitoring. |

Versioned under `/v1/` so the envelope can evolve.

### 5.2 Response envelope

`GET /v1/config` →

```json
{
  "config": "vpn://<base64url-no-pad of the Amnezia config JSON, see §5.3>",
  "sig":    "<base64std of Ed25519 signature over the exact UTF-8 bytes of the `config` string>",
  "alg":    "ed25519",
  "kid":    "nl-fleet-2026",
  "ts":     1730900000
}
```

- `config` — the payload the client applies (§5.3). **The signature is computed over the exact
  string value of this field, including the `vpn://` prefix.**
- `sig` — detached Ed25519 signature (Appendix D). Signing the `config` string (not the whole
  JSON) keeps verification stable regardless of JSON key ordering / whitespace.
- `alg` / `kid` — algorithm + key id, for future rotation.
- `ts` — issue time (unix seconds); a client may reject stale/replayed responses beyond a skew
  window. (In M1 the signature covers only `config`; see Appendix D for the M3 replay-hardening
  upgrade that also binds `ts`.)

**Backward-compat with today's client.** The current Amnezia parser (`fillServerConfig`) reads
**only** the `config` field and ignores unknown fields (Appendix A). So this envelope already
parses on an unmodified client, and a signature-aware client *additionally* checks `sig`. The
client change the issue asks for is therefore strictly additive.

### 5.3 The `config` payload (`vpn://…`)

The bytes inside `vpn://` are the standard Amnezia config JSON. To produce it, fleetcore
**inverts** what the client does (full algorithm in Appendix A):

1. Take the Amnezia config JSON (Appendix C is a complete, real example).
2. **Optionally** Qt-`qCompress` it (Appendix D.3). **MVP skips this** — plain JSON works
   because the client falls back to the raw bytes when decompression isn't applicable
   (Appendix A, step 6).
3. base64-encode with the **URL alphabet, no padding** (Go `base64.RawURLEncoding`). This must
   match the client's `Base64UrlEncoding | OmitTrailingEquals` decode.
4. Prefix with `vpn://`.

**Minimum shape of the decoded JSON** for a self-hosted AmneziaWG server (verified wire keys —
full table in Appendix B, complete example in Appendix C):

```json
{
  "hostName": "203.0.113.10",
  "dns1": "1.1.1.1",
  "dns2": "1.0.0.1",
  "config_version": 0,
  "defaultContainer": "amnezia-awg",
  "containers": [
    {
      "container": "amnezia-awg",
      "awg": {
        "port": "55424",
        "transport_proto": "udp",
        "last_config": "{ ...stringified inner client config, see Appendix C... }"
      }
    }
  ]
}
```

Three things that are easy to get wrong (all verified):

- The protocol sub-object key is **`"awg"`** (from `protoToString(Awg)`), **not**
  `"amnezia-awg"`. `"amnezia-awg"` is only the value of the sibling `"container"` field. Both
  `amnezia-awg` and `amnezia-awg2` store their protocol under the `"awg"` key.
- The config-source key is **`"config_version"`** (snake_case), not `configVersion`. Use `0`
  (or omit) for a native self-hosted config; the client then does **not** require `name` /
  `description`. Value `2` = AmneziaGateway (don't use — that's the premium path).
- `port` on the outer `awg` object is a **string**; inside `last_config` it is an **int**
  (Appendix C). The AmneziaWG obfuscation params (`Jc, Jmin, Jmax, S1..S4, H1..H4, I1..I5`) may
  be set on the outer `awg` object, but the client re-derives them from `last_config` anyway
  (Appendix A, step 8b) — so a correct `last_config` is the source of truth.

fleetcore stores each fleet member's ready-made config (exported from the operator's existing
setup) and returns the selected one; it does **not** synthesize crypto and does **not** need to
handle the `$WIREGUARD_CLIENT_PRIVATE_KEY` placeholder (that's a gateway-templating concern; a
self-hosted export already has the real key baked in).

## 6. Health & selection

> **Why this is more than a health check.** A naive "ping, switch on failure" loop turns
> transient loss into constant flapping and clients into a churning herd. The patterns below —
> smoothing, hysteresis, flap-scoring, and post-switch stickiness — exist specifically to make
> failover *stable*: switch when it genuinely helps, stay put otherwise. They are standard
> fleet-health engineering and are fully specified here; **no external code or system is
> required.**

Patterns to carry over:

1. **No single-probe truth.** A member is marked down only after a *smoothed window* of
   failures, never one missed packet. (Single-packet ICMP probes paint false "down".)
2. **Rise/fall hysteresis.** Separate consecutive-success (`rise`) and consecutive-failure
   (`fall`) thresholds before flipping state.
3. **Flap-scoring.** Penalize members that oscillate by *loss/latency* (soft flap), not just
   hard-dead ones, so selection doesn't keep bouncing onto a soft-flapping node.
4. **Post-switch stickiness / cooldown.** After advertising a new best, hold it for a cooldown
   before re-evaluating, to prevent two effects fighting and reconverging every cycle.
5. **Switch only on a real, lasting improvement.** Change the advertised best **only** when the
   current one is genuinely bad **and** the alternative is meaningfully and *durably* better —
   not on noise. "Zero switches when everything's fine" is success, not breakage.
6. **Signal-source discipline.** Selection reads *smoothed health windows*, not the last
   instantaneous sample.

Compact state machine (per member):

```
state ∈ {up, down};  okStreak, failStreak counters; flapScore (decays over flap_window)
on probe ok:   failStreak=0; okStreak++;   if state==down && okStreak>=rise: state=up
on probe fail: okStreak=0;  failStreak++;  if state==up   && failStreak>=fall: state=down; flapScore++
advertise():   among state==up members, rank by (priority asc, flapScore asc, weight);
               keep the current pick unless it is down OR a candidate is better by a margin
               AND switch_cooldown since last switch has elapsed (rules 4–5).
```

Selection strategies (config-selectable): `priority` (default), `weighted`, `roundrobin` — all
wrapped by rules 4–5 so the *advertised* choice is sticky even when the raw ranking wobbles.

## 7. Server configuration (`fleet.yaml`)

```yaml
listen: ":8443"
selection: priority          # priority | weighted | roundrobin
health:
  interval: 15s
  timeout: 3s
  rise: 2                     # consecutive OK to mark up
  fall: 3                     # consecutive fail to mark down
  flap_window: 10m           # window for flap-scoring
  switch_cooldown: 5m        # post-switch stickiness (rule 4)
signing:
  key_file: /keys/ed25519.key # private key, mounted — never in image
  kid: nl-fleet-2026
members:
  - label: nl-1
    priority: 10
    check: { type: tcp, target: "203.0.113.10:443" }
    config_file: /fleet/nl-1.amnezia.json   # decoded Amnezia config JSON (Appendix C)
  - label: de-1
    priority: 20
    check: { type: udp, target: "198.51.100.20:55424" }
    config_file: /fleet/de-1.amnezia.json
```

Check types: `tcp` (connect), `udp` (probe), `http` (GET a node healthz), `handshake`
(optional AWG/WG handshake probe). Start with `tcp`/`http`; richer probes are M2+.

## 8. CLI

- `fleetcore serve -c fleet.yaml` — run the service (default).
- `fleetcore keygen -o /keys/ed25519.key` — generate an Ed25519 keypair; print the public key
  as `ed25519:<base64std>` to embed in client configs.
- `fleetcore issue --endpoint https://cfg.example.net/v1/config --member nl-1` — emit a ready
  client `SelfHosted` config with the proposed extra fields:

```json
{
  "hostName": "203.0.113.10", "dns1": "1.1.1.1", "dns2": "1.0.0.1",
  "config_version": 0, "defaultContainer": "amnezia-awg",
  "containers": [ { "container": "amnezia-awg", "awg": { "...": "..." } } ],
  "update_endpoint": "https://cfg.example.net/v1/config",
  "update_pubkey": "ed25519:BASE64STD...",
  "update_interval_sec": 900
}
```

`update_endpoint` / `update_pubkey` / `update_interval_sec` are the fields the issue asks the
client to honor for `SelfHosted` configs. Named here for the reference; final names are the
client's call. (They are extra top-level keys the current parser ignores — Appendix A.)

## 9. Go layout

```
fleetcore/
  cmd/fleetcore/main.go        # CLI: serve | keygen | issue
  internal/
    api/       # HTTP handlers, envelope assembly (§5.2)
    fleet/     # inventory + selection (§6)
    health/    # checkers + smoothed state machine (§6)
    vpnblob/   # vpn:// encode: base64url(+optional qCompress) (§5.3, App. A/D)
    sign/      # ed25519 sign / pubkey export (App. D)
    config/    # fleet.yaml load + validate
  deploy/
    Dockerfile             # multi-stage -> distroless/static, ~10 MB
    docker-compose.yml
    fleet.example.yaml
    fleet/nl-1.amnezia.json  # example member config (Appendix C)
  DESIGN.md
  README.md
  LICENSE
```

**Dependencies (all stdlib except YAML):** `crypto/ed25519`, `encoding/base64`
(`RawURLEncoding` for the payload, `StdEncoding` for sig/pubkey), `encoding/json`,
`compress/zlib` + `encoding/binary` (only if `--compress` is implemented),
`net/http`, `gopkg.in/yaml.v3` for `fleet.yaml`.

## 10. Container

- Multi-stage: `golang:… AS build` → static binary copied into `gcr.io/distroless/static`
  (or `scratch`). Tiny, no shell, minimal CVE surface.
- All runtime inputs are mounts/env: `/keys` (private key), `/fleet` (member configs),
  `fleet.yaml`.

```
docker run --rm -p 8443:8443 \
  -v $PWD/fleet.yaml:/etc/fleetcore/fleet.yaml:ro \
  -v $PWD/fleet:/fleet:ro \
  -v $PWD/keys:/keys:ro \
  ghcr.io/<you>/fleetcore:latest serve -c /etc/fleetcore/fleet.yaml
```

- TLS: terminate at a reverse proxy (Caddy/nginx) or pass `--tls-cert/--tls-key`. The
  signature makes plain HTTP safe for integrity; HTTPS is for privacy.

## 11. Milestones

- **M1 (MVP):** `serve` + `keygen`, single-member static config, Ed25519-signed envelope,
  uncompressed `vpn://`, Dockerfile, client-stub acceptance test (Appendix E). Enough to attach
  to the issue and demo end-to-end.
- **M2:** multi-member fleet + health checks + smoothed `priority` selection (§6 rules 1–4).
- **M3:** `issue` tool, weighted/round-robin, justified+curative gating (rule 5), `ts`-bound
  signature for replay protection (Appendix D), key rotation via `kid`.
- **M4 (optional):** qCompress-compatible payloads, Prometheus `/metrics`, config caching.

## 12. Relationship to the issue

- The **issue** describes the *client* change (honor an update endpoint + pinned key on
  `SelfHosted` configs) and stays product-neutral.
- **fleetcore** is a runnable *server* speaking that protocol. Link it from the issue as a
  companion reference so maintainers can run the full loop.

---

# Appendix A — Client decode contract (what fleetcore must invert)

Verified against `apiConfigsController.cpp::fillServerConfig` at tag **4.8.19.0** (lines
~162–254). The server produces a response body that this function turns into a usable config;
to interoperate, fleetcore inverts steps 1–7.

1. **JSON-parse** the raw HTTP body; read the top-level string field **`config`**.
2. **Strip `vpn://`** via `QString::replace("vpn://","")` — note this removes *all*
   occurrences, so never put `vpn://` anywhere but the prefix.
3. **base64-decode** with `QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals` →
   **URL alphabet (`-`/`_`), no `=` padding.** (Decode is padding-tolerant, but the canonical
   wire form is unpadded — emit unpadded.)
4. **Empty guard:** empty decode → error.
5. **`qUncompress`** the bytes.
6. **Compression fallback (load-bearing):** `qUncompress` expects Qt framing = **4-byte
   big-endian uint32 uncompressed-size prefix + a zlib stream**. If the input is *not* in that
   format (e.g. plain JSON, or a bare zlib stream with no size prefix), `qUncompress` returns
   **empty**, and the client keeps the **original** bytes. ⇒ fleetcore may send **either**
   qCompress-framed JSON **or** plain JSON. It must **not** send bare zlib/gzip or any other
   compression (those neither match qCompress framing nor survive the fallback).
7. The resulting UTF-8 bytes are the **config JSON** (§5.3 / Appendix C).
8. Protocol-specific rewrite on the JSON:
   - **cloak:** minor `<key>` newline fix + `$OPENVPN_PRIV_KEY` substitution.
   - **awg:** replace token `$WIREGUARD_CLIENT_PRIVATE_KEY` (no-op for a baked self-hosted
     config), then hoist the AmneziaWG junk params (`Jc,Jmin,Jmax,S1..S4,H1..H4,I1..I5`) out of
     `containers[0].awg.last_config` onto `containers[0].awg`.
9. **Fields copied out** into the client's serverConfig: **always** `dns1`, `dns2`,
   `containers`, `hostName`, `defaultContainer`; **only when `config_version == 2`** also
   `config_version`, `name`, `description`, plus `supported_protocols` / `service_info` merged
   from the raw response top level. → For self-hosted (`config_version` 0/absent) you only need
   `hostName`, `dns1`, `dns2`, `containers`, `defaultContainer`.
10. **Unknown top-level fields are ignored** — this is why the envelope's `sig`/`alg`/`kid`/`ts`
    and the client config's `update_*` fields are safe/backward-compatible.

# Appendix B — Wire key reference

Exact string literals from `client/protocols/protocols_defs.h` (namespace `amnezia::config_key`),
each individually verified. Symbol → wire string:

| C++ symbol | wire key | notes |
|---|---|---|
| `config` | `config` | top-level envelope field holding the `vpn://` blob |
| `hostName` | `hostName` | server host/IP |
| `dns1` / `dns2` | `dns1` / `dns2` | resolver IPs |
| `configVersion` | `config_version` | **snake_case**; 0/absent=self-hosted, 2=gateway |
| `defaultContainer` | `defaultContainer` | e.g. `amnezia-awg` |
| `description` / `name` | `description` / `name` | only read when `config_version==2` |
| `containers` | `containers` | array; only index 0 read for AWG |
| `container` | `container` | container id string, e.g. `amnezia-awg` |
| `last_config` | `last_config` | **stringified** inner client config JSON |
| `port` | `port` | string on outer `awg`, int inside `last_config` |
| `transport_proto` | `transport_proto` | `udp` for awg |
| `junkPacketCount` | `Jc` | AmneziaWG obfuscation params ↓ |
| `junkPacketMinSize` / `junkPacketMaxSize` | `Jmin` / `Jmax` | |
| `initPacketJunkSize` / `responsePacketJunkSize` | `S1` / `S2` | |
| `cookieReplyPacketJunkSize` / `transportPacketJunkSize` | `S3` / `S4` | Awg2 only |
| `initPacketMagicHeader` … `transportPacketMagicHeader` | `H1` … `H4` | |
| `specialJunk1` … `specialJunk5` | `I1` … `I5` | I1 default is the iCloud-looking blob |

**Container shape (verified):** each `containers[]` element is
`{ "container": "amnezia-awg", "awg": { …protocol config… } }`. The protocol sub-object key is
`protoToString(Awg)` = **`"awg"`** (also for `amnezia-awg2`), **not** the `container` value.
For reference: WireGuard → field `amnezia-wireguard`, key `wireguard`; OpenVPN →
`amnezia-openvpn` / `openvpn`. (`ContainerProps::containerToString` /
`containerTypeToString`, `containers_defs.cpp`.)

# Appendix C — Canonical example payload

A complete, real-shaped decoded AmneziaWG **self-hosted** config (placeholders in CAPS). This
is exactly the JSON that gets `base64url`-wrapped into `vpn://…`. Ship it as
`deploy/fleet/nl-1.amnezia.json` and use it as the M1 fixture.

```json
{
  "hostName": "SERVER_PUBLIC_IP",
  "dns1": "1.1.1.1",
  "dns2": "1.0.0.1",
  "config_version": 0,
  "defaultContainer": "amnezia-awg",
  "containers": [
    {
      "container": "amnezia-awg",
      "awg": {
        "port": "55424",
        "transport_proto": "udp",
        "subnet_address": "10.8.1.0",
        "mtu": "1376",
        "Jc": "5", "Jmin": "10", "Jmax": "50",
        "S1": "119", "S2": "38", "S3": "51", "S4": "12",
        "H1": "1148571719", "H2": "2137945458", "H3": "1250648369", "H4": "3925184142",
        "I1": "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>",
        "I2": "", "I3": "", "I4": "", "I5": "",
        "last_config": "{\"H1\":\"1148571719\",\"H2\":\"2137945458\",\"H3\":\"1250648369\",\"H4\":\"3925184142\",\"Jc\":\"5\",\"Jmax\":\"50\",\"Jmin\":\"10\",\"S1\":\"119\",\"S2\":\"38\",\"S3\":\"51\",\"S4\":\"12\",\"I1\":\"<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>\",\"I2\":\"\",\"I3\":\"\",\"I4\":\"\",\"I5\":\"\",\"allowed_ips\":[\"0.0.0.0/0\",\"::/0\"],\"clientId\":\"CLIENT_PUB_KEY_BASE64=\",\"client_ip\":\"10.8.1.2\",\"client_priv_key\":\"CLIENT_PRIV_KEY_BASE64=\",\"client_pub_key\":\"CLIENT_PUB_KEY_BASE64=\",\"config\":\"[Interface]\\nAddress = 10.8.1.2/32\\nDNS = 1.1.1.1, 1.0.0.1\\nPrivateKey = CLIENT_PRIV_KEY_BASE64=\\nJc = 5\\nJmin = 10\\nJmax = 50\\nS1 = 119\\nS2 = 38\\nS3 = 51\\nS4 = 12\\nH1 = 1148571719\\nH2 = 2137945458\\nH3 = 1250648369\\nH4 = 3925184142\\nI1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>\\nI2 = \\nI3 = \\nI4 = \\nI5 = \\n\\n[Peer]\\nPublicKey = SERVER_PUB_KEY_BASE64=\\nPresharedKey = PRESHARED_KEY_BASE64=\\nAllowedIPs = 0.0.0.0/0, ::/0\\nEndpoint = SERVER_PUBLIC_IP:55424\\nPersistentKeepalive = 25\\n\",\"hostName\":\"SERVER_PUBLIC_IP\",\"mtu\":\"1376\",\"persistent_keep_alive\":\"25\",\"port\":55424,\"psk_key\":\"PRESHARED_KEY_BASE64=\",\"server_pub_key\":\"SERVER_PUB_KEY_BASE64=\"}"
      }
    }
  ]
}
```

Notes:
- The inner `last_config` `config` field is the full client `.conf` text (literal `\n`
  newlines); its `[Interface]` lines are the source of truth for the junk params and its
  `[Peer] Endpoint` must point at this server. `port` there is an **int**.
- To rotate/fail-over, fleetcore just serves a *different member's* JSON of this same shape.
- Operators generate these once per server from their existing Amnezia setup (export a share
  config, base64url-decode it to get this JSON). fleetcore never mints keys.

# Appendix D — Crypto & encoding spec (canonical)

Because the client-side verifier is *proposed* (not yet implemented), fleetcore is the
authoritative definition. Keep it boring and exact so a client implementer can match it.

**D.1 Keys.** Ed25519 (RFC 8032). `keygen` produces a keypair; store the 32-byte seed (or full
64-byte private) in `key_file` (mode 0600, mounted). Advertise the public key as
`ed25519:<base64std(32-byte pubkey)>`. That string is what goes into the client config
`update_pubkey` and what `GET /v1/pubkey` returns.

**D.2 Signature.** `sig = base64std( Ed25519_Sign(priv, utf8bytes(config_string)) )`, where
`config_string` is the exact value of the envelope `config` field **including** the `vpn://`
prefix. Client verifies `Ed25519_Verify(pub, utf8bytes(config), base64std_decode(sig))`.
- Go sign: `base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(cfg)))`.
- `alg` must equal `"ed25519"`; reject unknown `alg`.
- **M3 replay hardening:** bind time by signing `cfg + "\n" + strconv.Itoa(ts)` and set
  `"alg":"ed25519-ts"`; the client checks `|now-ts| < skew`. M1/M2 sign `cfg` only.

**D.3 Payload base64.** `config` inner encoding is `base64.RawURLEncoding` (URL alphabet, **no
padding**) — matches the client's `Base64UrlEncoding | OmitTrailingEquals`. Do **not** use
`StdEncoding` or padded URL encoding for the payload.

**D.4 Optional qCompress framing (`--compress`, M4).** Qt `qUncompress` expects:
`[4-byte big-endian uint32 = len(rawJSON)] || zlib.Deflate(rawJSON)`. In Go:
```go
var buf bytes.Buffer
binary.Write(&buf, binary.BigEndian, uint32(len(raw)))   // ACTUAL uncompressed size — not a placeholder
zw := zlib.NewWriter(&buf); zw.Write(raw); zw.Close()
blob := buf.Bytes()                                       // then base64.RawURLEncoding(blob)
```
Writing a wrong size in those 4 bytes makes `qUncompress` fail → the client silently falls back
to the still-compressed bytes → JSON parse yields an empty object. MVP avoids this entirely by
sending plain JSON.

# Appendix E — Client-stub acceptance test (M1 done-definition)

A ~40-line Go test/tool that plays the (proposed) client, proving the loop end-to-end without
the real app:

1. `GET /v1/config`; parse the envelope.
2. Verify `alg=="ed25519"` and `Ed25519_Verify(pinnedPub, []byte(env.config), b64std(env.sig))`.
3. Strip `vpn://`, `base64.RawURLEncoding.DecodeString`, (try qUncompress-equivalent, else raw),
   `json.Unmarshal`.
4. Assert: `hostName` non-empty; `containers[0].container == "amnezia-awg"`;
   `containers[0].awg.last_config` parses as JSON and its `config` contains a `[Peer] Endpoint`
   matching `hostName`.
5. Negative tests: a tampered `config` byte ⇒ signature fails; wrong pinned key ⇒ fails.

This is the M1 gate and doubles as the demo script to link from the issue.

# Appendix F — Source references

Verified against `amnezia-vpn/amnezia-client`. Permalinks (decode logic at `4.8.19.0`):

- Decode: `client/ui/controllers/api/apiConfigsController.cpp` `fillServerConfig`
  — https://github.com/amnezia-vpn/amnezia-client/blob/4.8.19.0/client/ui/controllers/api/apiConfigsController.cpp#L159
- Config types / keys: `client/core/api/apiDefs.h`
  — https://github.com/amnezia-vpn/amnezia-client/blob/4.8.19.0/client/core/api/apiDefs.h#L8-L16
- Wire-key literals: `client/protocols/protocols_defs.h` namespace `amnezia::config_key`
  (`hostName`:14, `dns1/2`:20-21, `config`:27, `containers`:29, `container`:30,
  `defaultContainer`:31, `transport_proto`:37, `last_config`:65, `Jc..I5`:70-85,
  `config_version`:99) — https://github.com/amnezia-vpn/amnezia-client/blob/4.8.19.0/client/protocols/protocols_defs.h
- Container strings: `client/containers/containers_defs.cpp`
  (`containerToString` → `amnezia-awg`; `containerTypeToString` → `awg`)
  — https://github.com/amnezia-vpn/amnezia-client/blob/4.8.19.0/client/containers/containers_defs.cpp

> Provenance note: line numbers for `protocols_defs.h` / `containers_defs.cpp` were read at tag
> `4.8.15.4`; the string literals are identical at `4.8.19.0`. If a future check finds drift,
> the literals in Appendix B are the contract — re-derive line numbers from the symbol names.

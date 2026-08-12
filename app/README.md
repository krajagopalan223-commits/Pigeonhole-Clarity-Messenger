# Clarity Messenger — Flutter app

One Flutter/Dart codebase targeting **iOS, Android, and Linux**, talking to the
Rust `clarity-core` through `dart:ffi` (see `../ffi/include/clarity.h`) and to a
`clarity-relay` server over HTTPS.

```
lib/
  main.dart                        app entry; reads --dart-define transport config
  src/ffi/clarity_bindings.dart    raw dart:ffi bindings to the C ABI
  src/ffi/clarity.dart             safe wrapper: Clarity / Account / Session
  src/services/transport_config.dart  transport mode (direct / Tor / mesh)
  src/services/relay_worker.dart   background isolate owning the relay/Tor transport
  src/services/mesh_service.dart   mesh bridge + MeshRadio interface
  src/state/app_state.dart         account, sessions, contacts, persistence, polling
  src/models/models.dart           UI data models
  src/ui/                          home + chat screens
```

## How networking works (and why it isn't in Dart)

All network I/O goes through the Rust transports via FFI, not through Dart's
HTTP stack. That is deliberate: Dart has no SOCKS support, so routing over
**Tor** — and the Bluetooth mesh routing — must live in the native core to work
uniformly on every platform.

Relay/Tor calls **block** (a Tor request can take seconds), so `RelayWorker`
owns them on a dedicated background **isolate**. It exchanges only *bytes* with
the UI isolate — never `Account`/`Session` pointers — so there is no
cross-thread access to shared native state. Mesh calls are pure computation and
run inline.

## Platform runner folders

The **Linux** runner is committed (`linux/`), including the CMake rule that
bundles the native library — `flutter pub get && flutter build linux` works
as-is. The Android and iOS runners are machine-generated and not yet in the
repo; create them once, on a machine with Flutter installed:

```bash
cd app
flutter create --platforms=android,ios .
flutter pub get
```

`flutter create` only adds the missing runner scaffolding; it leaves the `lib/`,
`pubspec.yaml`, and `analysis_options.yaml` in this repo untouched.

## Tests

`test/models_test.dart` covers the pure-Dart pieces and runs anywhere. The
integration suite `test/ffi_roundtrip_test.dart` drives the real native
library through the same wrapper the app uses — PQXDH handshake, Double
Ratchet both directions, tamper rejection, safety numbers, account/session
serialize-restore, and mesh delivery over a loopback radio. It needs
`libclarity_ffi.so` on the loader path and skips itself (with instructions)
when the library is missing:

```bash
tool/build_rust.sh linux          # from the repo root, once
cd app
LD_LIBRARY_PATH=../target/release flutter test
```

For manually exercising a running app, `net/examples/demo_peer.rs` acts as a
second user from the command line — it fetches your bundle from a relay, opens
a session, sends one encrypted message, and decrypts your reply:

```bash
cargo run -p clarity-net --release --example demo_peer -- \
  http://127.0.0.1:8080 '<identity key from the app, base64>' 'hello'
```

## Build the native core and wire it in

From the repo root, build `clarity-core` for your target and place the library
where the Flutter build looks for it:

```bash
tool/build_rust.sh linux     # or: android | ios
```

### Linux
`tool/build_rust.sh linux` copies `libclarity_ffi.so` to `app/linux/lib/`
(gitignored). The committed `app/linux/CMakeLists.txt` already contains the
install rule that bundles it next to the executable, so after the script just
run `flutter build linux`. The app loads it by name via
`DynamicLibrary.open('libclarity_ffi.so')`.

### Android
Install the toolchain once:

```bash
cargo install cargo-ndk
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
```

Then `tool/build_rust.sh android` writes the per-ABI `.so` files under
`app/android/app/src/main/jniLibs/`, which Gradle packages automatically.

### iOS
```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
tool/build_rust.sh ios
```

In Xcode (`app/ios/Runner.xcworkspace`): add the correct `libclarity_ffi.a`
(device vs. simulator) under *Build Phases → Link Binary With Libraries*. The app
resolves symbols from the process image via `DynamicLibrary.process()`.

## Run

Start a relay (from repo root):

```bash
cargo run -p clarity-relay -- 127.0.0.1:8080
```

Then run the app, pointing it at the relay:

```bash
cd app
flutter run --dart-define=CLARITY_RELAY=http://127.0.0.1:8080
```

Over Tor (system `tor` on Linux, Orbot on Android), pointing at an onion relay:

```bash
flutter run \
  --dart-define=CLARITY_RELAY=http://<relay>.onion \
  --dart-define=CLARITY_TOR=true \
  --dart-define=CLARITY_SOCKS=127.0.0.1:9050
```

Tor can also be toggled at runtime from the transport button in the app bar.

> Android emulator note: reach a relay on the host machine at
> `http://10.0.2.2:8080`.

## Enabling the Bluetooth mesh

`clarity-mesh` provides the routing; the app must supply the radio. Implement
the `MeshRadio` interface (in `src/services/mesh_service.dart`) with a platform
plugin — Android Nearby Connections / BLE, iOS MultipeerConnectivity, or BlueZ
on Linux — and pass it to `AppState(meshRadio: ...)`. Then select
`TransportMode.mesh`.

Note the trade-off before enabling it: the mesh works with no internet at all,
but joining one **broadcasts your presence**. See `../MESH.md`.

## Current limitations (honest scope)

- **Only the Linux build has been exercised.** On Linux the app builds, passes
  `flutter analyze` with zero issues, passes its Dart test suite (see below),
  and has exchanged live encrypted messages with a second client through a
  relay, restoring account/contacts/sessions across a restart. iOS and Android
  have never been compiled — expect ordinary compile fixes on their first
  builds; the Rust side underneath is fully tested everywhere.
- **Bundle fetch needs a relay.** In pure-mesh mode there is no prekey
  directory, so contacts must exchange bundles some other way; today
  `addContact` requires a relay transport.
- **Relay metadata is minimized, not erased.** Payloads travel in sealed
  envelopes addressed to rotating inbox IDs and padded to size buckets, so
  the relay sees no sender, no stable recipient, and only bucketed sizes —
  but it still sees your network address (run over Tor), message counts and
  timing, and identity-keyed bundle fetches when adding a new contact.
  Mesh couriers carry sealed envelopes but route by recipient identity.
- **1:1 messaging only.** Group messaging (MLS/TreeKEM) is deferred to a
  dedicated, audited implementation.

Account, contacts, live Double Ratchet **session state, and message history
are persisted** via `flutter_secure_storage` (Keychain / Android Keystore /
libsecret), so conversations — including their text — survive an app restart.
Each conversation has a **disappearing-messages timer** (off / 1 h / 1 d /
1 w) that deletes older messages from this device's history; the timer is not
yet synced to the contact, and the UI says so.

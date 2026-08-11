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

## Why this folder isn't a full Flutter project yet

The platform runner folders (`android/`, `ios/`, `linux/`, …) are machine- and
Flutter-version-specific and are normally generated, not hand-written. Generate
them once, on a machine with Flutter installed:

```bash
cd app
flutter create --platforms=android,ios,linux .
flutter pub get
```

`flutter create` only adds the missing runner scaffolding; it leaves the `lib/`,
`pubspec.yaml`, and `analysis_options.yaml` in this repo untouched.

## Build the native core and wire it in

From the repo root, build `clarity-core` for your target and place the library
where the Flutter build looks for it:

```bash
tool/build_rust.sh linux     # or: android | ios
```

### Linux
`tool/build_rust.sh linux` copies `libclarity_ffi.so` to `app/linux/lib/`. Add
this to `app/linux/CMakeLists.txt` so it's bundled next to the executable:

```cmake
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/lib/libclarity_ffi.so"
        DESTINATION "${INSTALL_BUNDLE_LIB_DIR}" COMPONENT Runtime)
```

The app loads it by name via `DynamicLibrary.open('libclarity_ffi.so')`.

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

- **The app has never been compiled.** Flutter isn't available in the
  environment this was written in, so the Dart code is unanalyzed and unrun.
  Expect ordinary compile fixes on the first build; the Rust side underneath it
  is fully tested.
- **Bundle fetch needs a relay.** In pure-mesh mode there is no prekey
  directory, so contacts must exchange bundles some other way; today
  `addContact` requires a relay transport.
- **Routing is by stable identity key**, which exposes a contact graph to the
  relay operator (and the sender identity to mesh couriers). See
  `../ARCHITECTURE.md` for the intended mitigation: run over Tor, and move to
  rotating inbox IDs.
- **1:1 messaging only.** Group messaging (MLS/TreeKEM) is deferred to a
  dedicated, audited implementation.

Account, contacts, and live Double Ratchet **session state are persisted** via
`flutter_secure_storage` (Keychain / Android Keystore / libsecret), so
conversations now survive an app restart.

# Clarity Messenger — Flutter app

One Flutter/Dart codebase targeting **iOS, Android, and Linux**, talking to the
Rust `clarity-core` through `dart:ffi` (see `../ffi/include/clarity.h`) and to a
`clarity-relay` server over HTTPS.

```
lib/
  main.dart                     app entry; reads --dart-define=CLARITY_RELAY
  src/ffi/clarity_bindings.dart raw dart:ffi bindings to the C ABI
  src/ffi/clarity.dart          safe wrapper: Clarity / Account / Session
  src/services/relay_client.dart HTTP client for the relay
  src/state/app_state.dart      account, sessions, contacts, polling loop
  src/models/models.dart        UI data models
  src/ui/                       home + chat screens
```

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

> Android emulator note: reach a relay on the host machine at
> `http://10.0.2.2:8080`.

## Current limitations (honest scope)

- **Sessions are in-memory.** The account (identity + prekeys) is persisted via
  `flutter_secure_storage` (Keychain / Keystore / libsecret), but live Double
  Ratchet session state is not serialized yet, so sessions re-establish after an
  app restart.
- **Relay routing is by identity key**, which exposes a contact graph to the
  relay operator. See `../ARCHITECTURE.md` for the metadata trade-off and the
  intended transport-layer mitigation (run over Tor; rotating inbox IDs).
- **1:1 messaging only.** Group messaging (MLS/TreeKEM) is deferred to a
  dedicated, audited implementation.

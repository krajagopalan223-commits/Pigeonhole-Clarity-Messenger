// Low-level dart:ffi bindings to the clarity-core C ABI (see ffi/include/clarity.h).
//
// This file mirrors the C header exactly. Nothing here is "safe" — allocation,
// freeing, and pointer lifetime are the caller's responsibility. The ergonomic,
// memory-safe API lives in `clarity.dart`, which is what app code should use.

import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

/// Opaque handle to a `ClarityAccount`.
final class ClarityAccount extends Opaque {}

/// Opaque handle to a `ClaritySession`.
final class ClaritySession extends Opaque {}

/// Mirrors `ClarityBuffer` — an owned byte buffer. A null [ptr] means error.
final class ClarityBuffer extends Struct {
  external Pointer<Uint8> ptr;

  @Size()
  external int len;
}

// --- Native function type aliases -----------------------------------------

typedef _BufferFreeNative = Void Function(ClarityBuffer);
typedef _BufferFree = void Function(ClarityBuffer);

typedef _StringFreeNative = Void Function(Pointer<Char>);
typedef _StringFree = void Function(Pointer<Char>);

typedef _AccountGenNative = Pointer<ClarityAccount> Function();
typedef _AccountGen = Pointer<ClarityAccount> Function();

typedef _AccountFreeNative = Void Function(Pointer<ClarityAccount>);
typedef _AccountFree = void Function(Pointer<ClarityAccount>);

typedef _AccountSerializeNative = ClarityBuffer Function(Pointer<ClarityAccount>);
typedef _AccountSerialize = ClarityBuffer Function(Pointer<ClarityAccount>);

typedef _AccountDeserNative = Pointer<ClarityAccount> Function(Pointer<Uint8>, Size);
typedef _AccountDeser = Pointer<ClarityAccount> Function(Pointer<Uint8>, int);

typedef _IdentityPubNative = Void Function(Pointer<ClarityAccount>, Pointer<Uint8>);
typedef _IdentityPub = void Function(Pointer<ClarityAccount>, Pointer<Uint8>);

typedef _AccountBufNative = ClarityBuffer Function(Pointer<ClarityAccount>);
typedef _AccountBuf = ClarityBuffer Function(Pointer<ClarityAccount>);

typedef _SessionInitNative = Pointer<ClaritySession> Function(
    Pointer<ClarityAccount>, Pointer<Uint8>, Size);
typedef _SessionInit = Pointer<ClaritySession> Function(
    Pointer<ClarityAccount>, Pointer<Uint8>, int);

typedef _SessionRespondNative = Pointer<ClaritySession> Function(
    Pointer<ClarityAccount>, Pointer<Uint8>, Size, Pointer<ClarityBuffer>);
typedef _SessionRespond = Pointer<ClaritySession> Function(
    Pointer<ClarityAccount>, Pointer<Uint8>, int, Pointer<ClarityBuffer>);

typedef _SessionCryptNative = ClarityBuffer Function(
    Pointer<ClaritySession>, Pointer<Uint8>, Size);
typedef _SessionCrypt = ClarityBuffer Function(
    Pointer<ClaritySession>, Pointer<Uint8>, int);

typedef _SessionFreeNative = Void Function(Pointer<ClaritySession>);
typedef _SessionFree = void Function(Pointer<ClaritySession>);

typedef _SafetyNumberNative = Pointer<Char> Function(Pointer<Uint8>, Pointer<Uint8>);
typedef _SafetyNumber = Pointer<Char> Function(Pointer<Uint8>, Pointer<Uint8>);

/// Resolved bindings to the shared clarity-core library.
class ClarityBindings {
  ClarityBindings(this._lib)
      : bufferFree = _lib.lookupFunction<_BufferFreeNative, _BufferFree>('clarity_buffer_free'),
        stringFree = _lib.lookupFunction<_StringFreeNative, _StringFree>('clarity_string_free'),
        accountGenerate =
            _lib.lookupFunction<_AccountGenNative, _AccountGen>('clarity_account_generate'),
        accountFree =
            _lib.lookupFunction<_AccountFreeNative, _AccountFree>('clarity_account_free'),
        accountSerialize = _lib
            .lookupFunction<_AccountSerializeNative, _AccountSerialize>('clarity_account_serialize'),
        accountDeserialize = _lib
            .lookupFunction<_AccountDeserNative, _AccountDeser>('clarity_account_deserialize'),
        identityPublic = _lib.lookupFunction<_IdentityPubNative, _IdentityPub>(
            'clarity_account_identity_public'),
        bundleBase =
            _lib.lookupFunction<_AccountBufNative, _AccountBuf>('clarity_account_bundle_base'),
        oneTimePublics = _lib.lookupFunction<_AccountBufNative, _AccountBuf>(
            'clarity_account_one_time_publics'),
        sessionInitiate =
            _lib.lookupFunction<_SessionInitNative, _SessionInit>('clarity_session_initiate'),
        sessionRespond = _lib
            .lookupFunction<_SessionRespondNative, _SessionRespond>('clarity_session_respond'),
        sessionEncrypt =
            _lib.lookupFunction<_SessionCryptNative, _SessionCrypt>('clarity_session_encrypt'),
        sessionDecrypt =
            _lib.lookupFunction<_SessionCryptNative, _SessionCrypt>('clarity_session_decrypt'),
        sessionFree =
            _lib.lookupFunction<_SessionFreeNative, _SessionFree>('clarity_session_free'),
        safetyNumber =
            _lib.lookupFunction<_SafetyNumberNative, _SafetyNumber>('clarity_safety_number');

  final DynamicLibrary _lib;

  final _BufferFree bufferFree;
  final _StringFree stringFree;
  final _AccountGen accountGenerate;
  final _AccountFree accountFree;
  final _AccountSerialize accountSerialize;
  final _AccountDeser accountDeserialize;
  final _IdentityPub identityPublic;
  final _AccountBuf bundleBase;
  final _AccountBuf oneTimePublics;
  final _SessionInit sessionInitiate;
  final _SessionRespond sessionRespond;
  final _SessionCrypt sessionEncrypt;
  final _SessionCrypt sessionDecrypt;
  final _SessionFree sessionFree;
  final _SafetyNumber safetyNumber;

  /// Locate and open the clarity-core native library for the current platform.
  ///
  /// * Android / Linux: a shared `libclarity_ffi.so` bundled with the app.
  /// * iOS / macOS: statically linked into the app binary, so we look it up in
  ///   the already-loaded process image.
  static ClarityBindings open() {
    final DynamicLibrary lib;
    if (Platform.isIOS || Platform.isMacOS) {
      lib = DynamicLibrary.process();
    } else if (Platform.isAndroid || Platform.isLinux) {
      lib = DynamicLibrary.open('libclarity_ffi.so');
    } else if (Platform.isWindows) {
      lib = DynamicLibrary.open('clarity_ffi.dll');
    } else {
      throw UnsupportedError('Unsupported platform for clarity-core');
    }
    return ClarityBindings(lib);
  }
}

// Safe, idiomatic Dart wrapper over the clarity-core C ABI.
//
// App code uses only the types in this file — Account, Session, Clarity — and
// never touches raw pointers. All native allocations are freed here, including
// on error paths.

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'clarity_bindings.dart';

/// Entry point: holds the resolved native bindings.
class Clarity {
  Clarity._(this._b);

  final ClarityBindings _b;

  static Clarity? _instance;

  /// Open the native library once and cache it.
  static Clarity instance() => _instance ??= Clarity._(ClarityBindings.open());

  /// The resolved bindings, for same-isolate native components (e.g. the mesh).
  ClarityBindings get bindings => _b;

  /// Restore a session persisted with [Session.serialize].
  Session restoreSession(Uint8List bytes) {
    final input = _toNative(bytes);
    try {
      final ptr = _b.sessionDeserialize(input, bytes.length);
      if (ptr == nullptr) {
        throw const ClarityException('failed to restore session');
      }
      return Session._(_b, ptr);
    } finally {
      malloc.free(input);
    }
  }

  /// Create a brand-new identity/account.
  Account generateAccount() => Account._(_b, _b.accountGenerate());

  /// Restore an account from previously serialized bytes.
  Account restoreAccount(Uint8List bytes) {
    final input = _toNative(bytes);
    try {
      final ptr = _b.accountDeserialize(input, bytes.length);
      if (ptr == nullptr) {
        throw const ClarityException('failed to restore account');
      }
      return Account._(_b, ptr);
    } finally {
      malloc.free(input);
    }
  }

  /// The inbox epoch (24-hour window) containing `unixSeconds`.
  int epochForUnix(int unixSeconds) => _b.epochForUnix(unixSeconds);

  /// The rotating inbox ID a contact's relay mail is addressed to in `epoch`.
  Uint8List inboxId(Uint8List identity, int epoch) {
    final id = _toNative(identity);
    final out = malloc<Uint8>(32);
    try {
      _b.inboxId(id, epoch, out);
      return Uint8List.fromList(out.asTypedList(32));
    } finally {
      malloc.free(id);
      malloc.free(out);
    }
  }

  /// Decode and signature-verify a prekey bundle, returning the owner's
  /// Ed25519 identity and X25519 identity-DH (sealing) keys.
  ({Uint8List identityEd, Uint8List identityDh}) bundleIdentityKeys(Uint8List bundle) {
    final input = _toNative(bundle);
    final outEd = malloc<Uint8>(32);
    final outDh = malloc<Uint8>(32);
    try {
      final rc = _b.bundleIdentityKeys(input, bundle.length, outEd, outDh);
      if (rc != 0) {
        throw const ClarityException('bundle rejected (bad signature or malformed)');
      }
      return (
        identityEd: Uint8List.fromList(outEd.asTypedList(32)),
        identityDh: Uint8List.fromList(outDh.asTypedList(32)),
      );
    } finally {
      malloc.free(input);
      malloc.free(outEd);
      malloc.free(outDh);
    }
  }

  /// Compute the 60-digit safety number for two identity keys.
  String safetyNumber(Uint8List idA, Uint8List idB) {
    final a = _toNative(idA);
    final b = _toNative(idB);
    try {
      final strPtr = _b.safetyNumber(a, b);
      if (strPtr == nullptr) throw const ClarityException('safety number failed');
      try {
        return strPtr.cast<Utf8>().toDartString();
      } finally {
        _b.stringFree(strPtr);
      }
    } finally {
      malloc.free(a);
      malloc.free(b);
    }
  }

  Pointer<Uint8> _toNative(Uint8List data) {
    final ptr = malloc<Uint8>(data.isEmpty ? 1 : data.length);
    if (data.isNotEmpty) {
      ptr.asTypedList(data.length).setAll(0, data);
    }
    return ptr;
  }

  Uint8List _takeBuffer(ClarityBuffer buf) {
    if (buf.ptr == nullptr) {
      throw const ClarityException('native operation failed');
    }
    final out = Uint8List.fromList(buf.ptr.asTypedList(buf.len));
    _b.bufferFree(buf);
    return out;
  }
}

/// A local identity + its prekeys. Dispose with [dispose].
class Account {
  Account._(this._b, this._ptr);

  final ClarityBindings _b;
  Pointer<ClarityAccount> _ptr;
  bool _disposed = false;

  Pointer<ClarityAccount> get _handle {
    if (_disposed) throw StateError('Account already disposed');
    return _ptr;
  }

  /// The stable 32-byte identity public key (basis of the safety number).
  Uint8List identityPublic() {
    final out = malloc<Uint8>(32);
    try {
      _b.identityPublic(_handle, out);
      return Uint8List.fromList(out.asTypedList(32));
    } finally {
      malloc.free(out);
    }
  }

  /// The base prekey bundle (no one-time prekey) to upload to a relay.
  Uint8List bundleBase() => Clarity.instance()._takeBuffer(_b.bundleBase(_handle));

  /// One-time prekey publics as a decoded JSON list of `{id, public}` maps.
  List<Map<String, dynamic>> oneTimePublics() {
    final bytes = Clarity.instance()._takeBuffer(_b.oneTimePublics(_handle));
    final decoded = jsonDecode(utf8.decode(bytes)) as List<dynamic>;
    return decoded.cast<Map<String, dynamic>>();
  }

  /// Serialize the full secret state for encrypted-at-rest storage.
  Uint8List serialize() => Clarity.instance()._takeBuffer(_b.accountSerialize(_handle));

  /// Begin a session with a contact from their (verified) bundle bytes.
  Session initiateSession(Uint8List bundle) {
    final c = Clarity.instance();
    final input = c._toNative(bundle);
    try {
      final ptr = _b.sessionInitiate(_handle, input, bundle.length);
      if (ptr == nullptr) {
        throw const ClarityException('bundle rejected (bad signature or malformed)');
      }
      return Session._(_b, ptr);
    } finally {
      malloc.free(input);
    }
  }

  /// Accept an inbound first message, establishing a session and returning it
  /// alongside the decrypted first plaintext.
  (Session, Uint8List) respondToSession(Uint8List firstMessage) {
    final c = Clarity.instance();
    final input = c._toNative(firstMessage);
    final outBuf = malloc<ClarityBuffer>();
    try {
      final ptr = _b.sessionRespond(_handle, input, firstMessage.length, outBuf);
      if (ptr == nullptr) {
        throw const ClarityException('could not establish session from message');
      }
      final plaintext = c._takeBuffer(outBuf.ref);
      return (Session._(_b, ptr), plaintext);
    } finally {
      malloc.free(input);
      malloc.free(outBuf);
    }
  }

  /// Seal a payload to a recipient's X25519 identity DH key. Our identity
  /// keys travel *inside* the encryption; the transport sees only an
  /// ephemeral key and ciphertext.
  Uint8List sealEnvelope(Uint8List recipientIdentityDh, Uint8List payload) {
    final c = Clarity.instance();
    final dh = c._toNative(recipientIdentityDh);
    final input = c._toNative(payload);
    try {
      return c._takeBuffer(_b.sealEnvelope(_handle, dh, input, payload.length));
    } finally {
      malloc.free(dh);
      malloc.free(input);
    }
  }

  /// Open a sealed envelope addressed to this account. Throws
  /// [ClarityException] for anything malformed, tampered, or sealed to
  /// someone else. The claimed sender is only authenticated by successfully
  /// decrypting [OpenedEnvelope.payload] with a session.
  OpenedEnvelope openEnvelope(Uint8List blob) {
    final c = Clarity.instance();
    final input = c._toNative(blob);
    final outEd = malloc<Uint8>(32);
    final outDh = malloc<Uint8>(32);
    try {
      final payload =
          c._takeBuffer(_b.openEnvelope(_handle, input, blob.length, outEd, outDh));
      return OpenedEnvelope(
        senderIdentityEd: Uint8List.fromList(outEd.asTypedList(32)),
        senderIdentityDh: Uint8List.fromList(outDh.asTypedList(32)),
        payload: payload,
      );
    } finally {
      malloc.free(input);
      malloc.free(outEd);
      malloc.free(outDh);
    }
  }

  void dispose() {
    if (_disposed) return;
    _b.accountFree(_ptr);
    _ptr = nullptr;
    _disposed = true;
  }
}

/// A successfully opened sealed envelope: who claims to have sent it (verify
/// by decrypting!), their sealing key for replies, and the inner wire bytes.
class OpenedEnvelope {
  OpenedEnvelope({
    required this.senderIdentityEd,
    required this.senderIdentityDh,
    required this.payload,
  });

  final Uint8List senderIdentityEd;
  final Uint8List senderIdentityDh;
  final Uint8List payload;
}

/// One end of an encrypted conversation. Dispose with [dispose].
class Session {
  Session._(this._b, this._ptr);

  final ClarityBindings _b;
  Pointer<ClaritySession> _ptr;
  bool _disposed = false;

  Pointer<ClaritySession> get _handle {
    if (_disposed) throw StateError('Session already disposed');
    return _ptr;
  }

  /// Encrypt plaintext into an encoded wire message.
  Uint8List encrypt(Uint8List plaintext) {
    final c = Clarity.instance();
    final input = c._toNative(plaintext);
    try {
      return c._takeBuffer(_b.sessionEncrypt(_handle, input, plaintext.length));
    } finally {
      malloc.free(input);
    }
  }

  /// Decrypt an encoded wire message into plaintext.
  Uint8List decrypt(Uint8List message) {
    final c = Clarity.instance();
    final input = c._toNative(message);
    try {
      return c._takeBuffer(_b.sessionDecrypt(_handle, input, message.length));
    } finally {
      malloc.free(input);
    }
  }

  /// Serialize this session so the conversation survives an app restart. The
  /// result is SECRET — persist it only in OS secure storage.
  Uint8List serialize() => Clarity.instance()._takeBuffer(_b.sessionSerialize(_handle));

  void dispose() {
    if (_disposed) return;
    _b.sessionFree(_ptr);
    _ptr = nullptr;
    _disposed = true;
  }
}

/// Decode the FFI list format `[u32 count]([u32 len][bytes])*` (little-endian)
/// used by relay-poll and the mesh functions to return multiple buffers.
List<Uint8List> decodeByteList(Uint8List bytes) {
  if (bytes.length < 4) return const [];
  final data = ByteData.sublistView(bytes);
  final count = data.getUint32(0, Endian.little);
  var offset = 4;
  final out = <Uint8List>[];
  for (var i = 0; i < count; i++) {
    final len = data.getUint32(offset, Endian.little);
    offset += 4;
    out.add(Uint8List.fromList(Uint8List.sublistView(bytes, offset, offset + len)));
    offset += len;
  }
  return out;
}

/// Thrown when a native clarity-core call fails.
class ClarityException implements Exception {
  const ClarityException(this.message);
  final String message;
  @override
  String toString() => 'ClarityException: $message';
}

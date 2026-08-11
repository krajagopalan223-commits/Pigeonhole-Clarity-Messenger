// Low-level dart:ffi bindings to the clarity-core C ABI (see ffi/include/clarity.h).
//
// This file mirrors the C header exactly. Nothing here is "safe" — allocation,
// freeing, and pointer lifetime are the caller's responsibility. The ergonomic,
// memory-safe API lives in `clarity.dart`, which is what app code should use.

import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

/// Opaque handles.
final class ClarityAccount extends Opaque {}

final class ClaritySession extends Opaque {}

final class RelayTransport extends Opaque {}

final class MeshNode extends Opaque {}

/// Mirrors `ClarityBuffer` — an owned byte buffer. A null [ptr] means error.
final class ClarityBuffer extends Struct {
  external Pointer<Uint8> ptr;

  @Size()
  external int len;
}

// --- Native signatures -----------------------------------------------------

typedef _BufferFreeNative = Void Function(ClarityBuffer);
typedef _BufferFree = void Function(ClarityBuffer);

typedef _StringFreeNative = Void Function(Pointer<Char>);
typedef _StringFree = void Function(Pointer<Char>);

typedef _AccountGenNative = Pointer<ClarityAccount> Function();
typedef _AccountGen = Pointer<ClarityAccount> Function();
typedef _AccountFreeNative = Void Function(Pointer<ClarityAccount>);
typedef _AccountFree = void Function(Pointer<ClarityAccount>);

typedef _AccountBufNative = ClarityBuffer Function(Pointer<ClarityAccount>);
typedef _AccountBuf = ClarityBuffer Function(Pointer<ClarityAccount>);

typedef _AccountDeserNative = Pointer<ClarityAccount> Function(Pointer<Uint8>, Size);
typedef _AccountDeser = Pointer<ClarityAccount> Function(Pointer<Uint8>, int);

typedef _IdentityPubNative = Void Function(Pointer<ClarityAccount>, Pointer<Uint8>);
typedef _IdentityPub = void Function(Pointer<ClarityAccount>, Pointer<Uint8>);

typedef _SessionInitNative = Pointer<ClaritySession> Function(
    Pointer<ClarityAccount>, Pointer<Uint8>, Size);
typedef _SessionInit = Pointer<ClaritySession> Function(
    Pointer<ClarityAccount>, Pointer<Uint8>, int);

typedef _SessionRespondNative = Pointer<ClaritySession> Function(
    Pointer<ClarityAccount>, Pointer<Uint8>, Size, Pointer<ClarityBuffer>);
typedef _SessionRespond = Pointer<ClaritySession> Function(
    Pointer<ClarityAccount>, Pointer<Uint8>, int, Pointer<ClarityBuffer>);

typedef _SessionCryptNative = ClarityBuffer Function(Pointer<ClaritySession>, Pointer<Uint8>, Size);
typedef _SessionCrypt = ClarityBuffer Function(Pointer<ClaritySession>, Pointer<Uint8>, int);

typedef _SessionSerNative = ClarityBuffer Function(Pointer<ClaritySession>);
typedef _SessionSer = ClarityBuffer Function(Pointer<ClaritySession>);

typedef _SessionDeserNative = Pointer<ClaritySession> Function(Pointer<Uint8>, Size);
typedef _SessionDeser = Pointer<ClaritySession> Function(Pointer<Uint8>, int);

typedef _SessionFreeNative = Void Function(Pointer<ClaritySession>);
typedef _SessionFree = void Function(Pointer<ClaritySession>);

typedef _SafetyNumberNative = Pointer<Char> Function(Pointer<Uint8>, Pointer<Uint8>);
typedef _SafetyNumber = Pointer<Char> Function(Pointer<Uint8>, Pointer<Uint8>);

// Relay transport
typedef _RelayDirectNative = Pointer<RelayTransport> Function(Pointer<Char>);
typedef _RelayDirect = Pointer<RelayTransport> Function(Pointer<Char>);
typedef _RelayTorNative = Pointer<RelayTransport> Function(Pointer<Char>, Pointer<Char>);
typedef _RelayTor = Pointer<RelayTransport> Function(Pointer<Char>, Pointer<Char>);
typedef _RelayFreeNative = Void Function(Pointer<RelayTransport>);
typedef _RelayFree = void Function(Pointer<RelayTransport>);
typedef _RelayPublishNative = Int32 Function(Pointer<RelayTransport>, Pointer<ClarityAccount>);
typedef _RelayPublish = int Function(Pointer<RelayTransport>, Pointer<ClarityAccount>);
typedef _RelayPublishBytesNative = Int32 Function(
    Pointer<RelayTransport>, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _RelayPublishBytes = int Function(
    Pointer<RelayTransport>, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _RelayFetchNative = ClarityBuffer Function(Pointer<RelayTransport>, Pointer<Uint8>);
typedef _RelayFetch = ClarityBuffer Function(Pointer<RelayTransport>, Pointer<Uint8>);
typedef _RelaySendNative = Int32 Function(
    Pointer<RelayTransport>, Pointer<Uint8>, Pointer<Uint8>, Size);
typedef _RelaySend = int Function(Pointer<RelayTransport>, Pointer<Uint8>, Pointer<Uint8>, int);
typedef _RelayPollNative = ClarityBuffer Function(Pointer<RelayTransport>, Pointer<Uint8>);
typedef _RelayPoll = ClarityBuffer Function(Pointer<RelayTransport>, Pointer<Uint8>);

// Mesh
typedef _MeshNewNative = Pointer<MeshNode> Function(Pointer<Uint8>);
typedef _MeshNew = Pointer<MeshNode> Function(Pointer<Uint8>);
typedef _MeshFreeNative = Void Function(Pointer<MeshNode>);
typedef _MeshFree = void Function(Pointer<MeshNode>);
typedef _MeshOriginateNative = ClarityBuffer Function(
    Pointer<MeshNode>, Pointer<Uint8>, Pointer<Uint8>, Size);
typedef _MeshOriginate = ClarityBuffer Function(Pointer<MeshNode>, Pointer<Uint8>, Pointer<Uint8>, int);
typedef _MeshIngestNative = Int32 Function(Pointer<MeshNode>, Pointer<Uint8>, Size);
typedef _MeshIngest = int Function(Pointer<MeshNode>, Pointer<Uint8>, int);
typedef _MeshBufNative = ClarityBuffer Function(Pointer<MeshNode>);
typedef _MeshBuf = ClarityBuffer Function(Pointer<MeshNode>);

/// Resolved bindings to the shared clarity-core library. Cheap to construct, so
/// each isolate that needs FFI opens its own (see `clarity.dart`).
class ClarityBindings {
  ClarityBindings(this._lib)
      : bufferFree = _lib.lookupFunction<_BufferFreeNative, _BufferFree>('clarity_buffer_free'),
        stringFree = _lib.lookupFunction<_StringFreeNative, _StringFree>('clarity_string_free'),
        accountGenerate =
            _lib.lookupFunction<_AccountGenNative, _AccountGen>('clarity_account_generate'),
        accountFree =
            _lib.lookupFunction<_AccountFreeNative, _AccountFree>('clarity_account_free'),
        accountSerialize =
            _lib.lookupFunction<_AccountBufNative, _AccountBuf>('clarity_account_serialize'),
        accountDeserialize =
            _lib.lookupFunction<_AccountDeserNative, _AccountDeser>('clarity_account_deserialize'),
        identityPublic = _lib.lookupFunction<_IdentityPubNative, _IdentityPub>(
            'clarity_account_identity_public'),
        bundleBase =
            _lib.lookupFunction<_AccountBufNative, _AccountBuf>('clarity_account_bundle_base'),
        oneTimePublics = _lib.lookupFunction<_AccountBufNative, _AccountBuf>(
            'clarity_account_one_time_publics'),
        sessionInitiate =
            _lib.lookupFunction<_SessionInitNative, _SessionInit>('clarity_session_initiate'),
        sessionRespond =
            _lib.lookupFunction<_SessionRespondNative, _SessionRespond>('clarity_session_respond'),
        sessionEncrypt =
            _lib.lookupFunction<_SessionCryptNative, _SessionCrypt>('clarity_session_encrypt'),
        sessionDecrypt =
            _lib.lookupFunction<_SessionCryptNative, _SessionCrypt>('clarity_session_decrypt'),
        sessionSerialize =
            _lib.lookupFunction<_SessionSerNative, _SessionSer>('clarity_session_serialize'),
        sessionDeserialize =
            _lib.lookupFunction<_SessionDeserNative, _SessionDeser>('clarity_session_deserialize'),
        sessionFree =
            _lib.lookupFunction<_SessionFreeNative, _SessionFree>('clarity_session_free'),
        safetyNumber =
            _lib.lookupFunction<_SafetyNumberNative, _SafetyNumber>('clarity_safety_number'),
        relayDirect =
            _lib.lookupFunction<_RelayDirectNative, _RelayDirect>('clarity_relay_transport_direct'),
        relayTor =
            _lib.lookupFunction<_RelayTorNative, _RelayTor>('clarity_relay_transport_tor'),
        relayFree =
            _lib.lookupFunction<_RelayFreeNative, _RelayFree>('clarity_relay_transport_free'),
        relayPublish = _lib
            .lookupFunction<_RelayPublishNative, _RelayPublish>('clarity_relay_publish_account'),
        relayPublishBytes = _lib.lookupFunction<_RelayPublishBytesNative, _RelayPublishBytes>(
            'clarity_relay_publish'),
        relayFetch =
            _lib.lookupFunction<_RelayFetchNative, _RelayFetch>('clarity_relay_fetch_bundle'),
        relaySend = _lib.lookupFunction<_RelaySendNative, _RelaySend>('clarity_relay_send'),
        relayPoll = _lib.lookupFunction<_RelayPollNative, _RelayPoll>('clarity_relay_poll'),
        meshNew = _lib.lookupFunction<_MeshNewNative, _MeshNew>('clarity_mesh_node_new'),
        meshFree = _lib.lookupFunction<_MeshFreeNative, _MeshFree>('clarity_mesh_node_free'),
        meshOriginate =
            _lib.lookupFunction<_MeshOriginateNative, _MeshOriginate>('clarity_mesh_originate'),
        meshIngest = _lib.lookupFunction<_MeshIngestNative, _MeshIngest>('clarity_mesh_ingest'),
        meshPendingBroadcast = _lib
            .lookupFunction<_MeshBufNative, _MeshBuf>('clarity_mesh_pending_broadcast'),
        meshTakeInbox =
            _lib.lookupFunction<_MeshBufNative, _MeshBuf>('clarity_mesh_take_inbox');

  final DynamicLibrary _lib;

  final _BufferFree bufferFree;
  final _StringFree stringFree;
  final Pointer<ClarityAccount> Function() accountGenerate;
  final _AccountFree accountFree;
  final _AccountBuf accountSerialize;
  final _AccountDeser accountDeserialize;
  final _IdentityPub identityPublic;
  final _AccountBuf bundleBase;
  final _AccountBuf oneTimePublics;
  final _SessionInit sessionInitiate;
  final _SessionRespond sessionRespond;
  final _SessionCrypt sessionEncrypt;
  final _SessionCrypt sessionDecrypt;
  final _SessionSer sessionSerialize;
  final _SessionDeser sessionDeserialize;
  final _SessionFree sessionFree;
  final _SafetyNumber safetyNumber;
  final _RelayDirect relayDirect;
  final _RelayTor relayTor;
  final _RelayFree relayFree;
  final _RelayPublish relayPublish;
  final _RelayPublishBytes relayPublishBytes;
  final _RelayFetch relayFetch;
  final _RelaySend relaySend;
  final _RelayPoll relayPoll;
  final _MeshNew meshNew;
  final _MeshFree meshFree;
  final _MeshOriginate meshOriginate;
  final _MeshIngest meshIngest;
  final _MeshBuf meshPendingBroadcast;
  final _MeshBuf meshTakeInbox;

  /// Locate and open the clarity-core native library for the current platform.
  static DynamicLibrary openLibrary() {
    if (Platform.isIOS || Platform.isMacOS) {
      return DynamicLibrary.process();
    } else if (Platform.isAndroid || Platform.isLinux) {
      return DynamicLibrary.open('libclarity_ffi.so');
    } else if (Platform.isWindows) {
      return DynamicLibrary.open('clarity_ffi.dll');
    }
    throw UnsupportedError('Unsupported platform for clarity-core');
  }

  static ClarityBindings open() => ClarityBindings(openLibrary());
}

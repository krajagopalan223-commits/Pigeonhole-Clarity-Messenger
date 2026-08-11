// Bluetooth mesh service: bridges the native routing engine (clarity-mesh via
// FFI) to a platform Bluetooth radio.
//
// The mesh FFI calls are pure computation (no I/O), so they run on the main
// isolate cheaply. The actual radio is abstracted behind [MeshRadio], which a
// platform plugin (Android Nearby / iOS MultipeerConnectivity / BlueZ)
// implements. This crate ships the routing + the bridge, not the radio.

import 'dart:async';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffi/clarity.dart';
import '../ffi/clarity_bindings.dart';

/// The Bluetooth radio, implemented by a platform plugin.
///
/// Contract: [incomingFrames] emits raw frame bytes received from peers;
/// [broadcast] transmits frames to any peer currently in range.
abstract class MeshRadio {
  Stream<Uint8List> get incomingFrames;
  Future<void> broadcast(List<Uint8List> frames);
  Future<void> start();
  Future<void> stop();
}

/// Drives a native mesh node with a [MeshRadio], surfacing delivered messages.
class MeshService {
  MeshService(this._radio, Uint8List myIdentity)
      : _bindings = Clarity.instance().bindings {
    _node = _createNode(myIdentity);
  }

  final MeshRadio _radio;
  final ClarityBindings _bindings;
  late final Pointer<MeshNode> _node;

  final _inbox = StreamController<Uint8List>.broadcast();
  StreamSubscription<Uint8List>? _radioSub;
  Timer? _rebroadcast;

  /// Delivered payloads addressed to us (opaque; decrypt with a Session).
  Stream<Uint8List> get inbox => _inbox.stream;

  /// Start radio + periodic carry-forward rebroadcast.
  Future<void> start() async {
    await _radio.start();
    _radioSub = _radio.incomingFrames.listen(_onFrame);
    // Periodically re-offer our carry-forward store to whoever is in range.
    _rebroadcast = Timer.periodic(const Duration(seconds: 5), (_) => _flush());
  }

  /// Inject an (already-encrypted) message toward a recipient and broadcast it.
  Future<void> send(Uint8List recipient, Uint8List encryptedPayload) async {
    final frame = _originate(recipient, encryptedPayload);
    await _radio.broadcast([frame]);
  }

  void _onFrame(Uint8List frameBytes) {
    _ingest(frameBytes);
    final delivered = _takeInbox();
    for (final payload in delivered) {
      _inbox.add(payload);
    }
  }

  Future<void> _flush() async {
    final pending = _pendingBroadcast();
    if (pending.isNotEmpty) {
      await _radio.broadcast(pending);
    }
  }

  Future<void> dispose() async {
    _rebroadcast?.cancel();
    await _radioSub?.cancel();
    await _radio.stop();
    await _inbox.close();
    _bindings.meshFree(_node);
  }

  // --- native helpers (main isolate; no I/O) ---------------------------------

  Pointer<MeshNode> _createNode(Uint8List id) {
    final p = malloc<Uint8>(32);
    try {
      p.asTypedList(32).setAll(0, id);
      final node = _bindings.meshNew(p);
      if (node == nullptr) throw const ClarityException('mesh node create failed');
      return node;
    } finally {
      malloc.free(p);
    }
  }

  Uint8List _originate(Uint8List recipient, Uint8List payload) {
    final r = malloc<Uint8>(32);
    final pl = malloc<Uint8>(payload.isEmpty ? 1 : payload.length);
    try {
      r.asTypedList(32).setAll(0, recipient);
      if (payload.isNotEmpty) pl.asTypedList(payload.length).setAll(0, payload);
      final buf = _bindings.meshOriginate(_node, r, pl, payload.length);
      return _take(buf);
    } finally {
      malloc.free(r);
      malloc.free(pl);
    }
  }

  void _ingest(Uint8List frame) {
    final f = malloc<Uint8>(frame.isEmpty ? 1 : frame.length);
    try {
      if (frame.isNotEmpty) f.asTypedList(frame.length).setAll(0, frame);
      _bindings.meshIngest(_node, f, frame.length);
    } finally {
      malloc.free(f);
    }
  }

  List<Uint8List> _pendingBroadcast() => decodeByteList(_take(_bindings.meshPendingBroadcast(_node)));

  List<Uint8List> _takeInbox() => decodeByteList(_take(_bindings.meshTakeInbox(_node)));

  Uint8List _take(ClarityBuffer buf) {
    if (buf.ptr == nullptr) return Uint8List(0);
    final out = Uint8List.fromList(buf.ptr.asTypedList(buf.len));
    _bindings.bufferFree(buf);
    return out;
  }
}

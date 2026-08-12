// Runs blocking relay/Tor FFI calls on a dedicated background isolate so the UI
// thread never stalls (a Tor request can take seconds).
//
// Why an isolate and not just `Isolate.run` per call: the relay transport owns a
// Tor connection we want to keep alive across calls, so one long-lived isolate
// owns one native `RelayTransport` handle and serves commands. Crucially, it
// exchanges only *bytes* with the main isolate — never Account/Session pointers —
// so there is no cross-thread access to shared mutable native state.

import 'dart:async';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffi/clarity.dart' show decodeByteList;
import '../ffi/clarity_bindings.dart';
import 'transport_config.dart';

/// A handle to the background relay isolate.
class RelayWorker {
  RelayWorker._(this._commands, this._isolate);

  final SendPort _commands;
  final Isolate _isolate;

  /// Spawn the worker for a given transport configuration.
  static Future<RelayWorker> start(TransportConfig config) async {
    final ready = ReceivePort();
    final isolate = await Isolate.spawn(
      _entry,
      _Boot(ready.sendPort, config.mode.name, config.relayUrl, config.torSocks),
    );
    final commands = await ready.first as SendPort;
    ready.close();
    return RelayWorker._(commands, isolate);
  }

  Future<dynamic> _call(String cmd, Map<String, dynamic> args) {
    final reply = ReceivePort();
    _commands.send({'reply': reply.sendPort, 'cmd': cmd, 'args': args});
    return reply.first.then((value) {
      reply.close();
      if (value is _WorkerError) {
        throw StateError('relay worker: ${value.message}');
      }
      return value;
    });
  }

  /// Publish a base bundle + one-time prekeys (JSON) to the relay.
  Future<bool> publish(Uint8List bundle, Uint8List oneTimeJson) async {
    final rc = await _call('publish', {'bundle': bundle, 'oneTime': oneTimeJson});
    return rc == 0;
  }

  /// Fetch a contact's bundle. Returns null if none is published.
  Future<Uint8List?> fetchBundle(Uint8List identity) async {
    final result = await _call('fetch', {'identity': identity});
    return result as Uint8List?;
  }

  /// Queue a message for a recipient.
  Future<bool> send(Uint8List recipient, Uint8List message) async {
    final rc = await _call('send', {'recipient': recipient, 'message': message});
    return rc == 0;
  }

  /// Drain queued messages for us. Returns the raw list-encoded bytes (decode
  /// with `decodeByteList`).
  Future<Uint8List> poll(Uint8List recipient) async {
    return await _call('poll', {'recipient': recipient}) as Uint8List;
  }

  /// Drain several mailboxes (a rotating-inbox window) in one isolate round
  /// trip, returning the individual envelopes in delivery order.
  Future<List<Uint8List>> pollMany(List<Uint8List> inboxes) async {
    final result = await _call('pollMany', {'inboxes': inboxes});
    return (result as List).cast<Uint8List>();
  }

  void dispose() {
    _commands.send({'cmd': 'shutdown'});
    _isolate.kill(priority: Isolate.beforeNextEvent);
  }

  // --- worker isolate --------------------------------------------------------

  static void _entry(_Boot boot) {
    final bindings = ClarityBindings.open();
    final url = boot.relayUrl.toNativeUtf8();
    final Pointer<RelayTransport> transport;
    if (boot.mode == TransportMode.relayTor.name) {
      final socks = boot.torSocks.toNativeUtf8();
      transport = bindings.relayTor(url.cast(), socks.cast());
      malloc.free(socks);
    } else {
      transport = bindings.relayDirect(url.cast());
    }
    malloc.free(url);

    final port = ReceivePort();
    boot.ready.send(port.sendPort);

    port.listen((message) {
      final map = message as Map;
      final cmd = map['cmd'] as String;
      if (cmd == 'shutdown') {
        if (transport != nullptr) bindings.relayFree(transport);
        port.close();
        return;
      }
      final reply = map['reply'] as SendPort;
      final args = (map['args'] as Map).cast<String, dynamic>();
      try {
        reply.send(_handle(bindings, transport, cmd, args));
      } catch (e) {
        reply.send(_WorkerError(e.toString()));
      }
    });
  }

  static dynamic _handle(
    ClarityBindings b,
    Pointer<RelayTransport> t,
    String cmd,
    Map<String, dynamic> args,
  ) {
    switch (cmd) {
      case 'publish':
        final bundle = _toNative(args['bundle'] as Uint8List);
        final oneTime = _toNative(args['oneTime'] as Uint8List);
        try {
          return b.relayPublishBytes(
            t,
            bundle.ptr,
            bundle.len,
            oneTime.ptr,
            oneTime.len,
          );
        } finally {
          malloc.free(bundle.ptr);
          malloc.free(oneTime.ptr);
        }
      case 'fetch':
        final id = _toNative(args['identity'] as Uint8List);
        try {
          final buf = b.relayFetch(t, id.ptr);
          if (buf.ptr == nullptr) {
            throw StateError('fetch transport error');
          }
          if (buf.len == 0) {
            b.bufferFree(buf);
            return null; // no bundle published
          }
          return _takeBuffer(b, buf);
        } finally {
          malloc.free(id.ptr);
        }
      case 'send':
        final recipient = _toNative(args['recipient'] as Uint8List);
        final msg = _toNative(args['message'] as Uint8List);
        try {
          return b.relaySend(t, recipient.ptr, msg.ptr, msg.len);
        } finally {
          malloc.free(recipient.ptr);
          malloc.free(msg.ptr);
        }
      case 'poll':
        final recipient = _toNative(args['recipient'] as Uint8List);
        try {
          final buf = b.relayPoll(t, recipient.ptr);
          if (buf.ptr == nullptr) throw StateError('poll transport error');
          return _takeBuffer(b, buf);
        } finally {
          malloc.free(recipient.ptr);
        }
      case 'pollMany':
        final inboxes = (args['inboxes'] as List).cast<Uint8List>();
        final envelopes = <Uint8List>[];
        for (final inbox in inboxes) {
          final id = _toNative(inbox);
          try {
            final buf = b.relayPoll(t, id.ptr);
            if (buf.ptr == nullptr) throw StateError('poll transport error');
            envelopes.addAll(decodeByteList(_takeBuffer(b, buf)));
          } finally {
            malloc.free(id.ptr);
          }
        }
        return envelopes;
      default:
        throw StateError('unknown command $cmd');
    }
  }

  static ({Pointer<Uint8> ptr, int len}) _toNative(Uint8List data) {
    final ptr = malloc<Uint8>(data.isEmpty ? 1 : data.length);
    if (data.isNotEmpty) ptr.asTypedList(data.length).setAll(0, data);
    return (ptr: ptr, len: data.length);
  }

  static Uint8List _takeBuffer(ClarityBindings b, ClarityBuffer buf) {
    final out = Uint8List.fromList(buf.ptr.asTypedList(buf.len));
    b.bufferFree(buf);
    return out;
  }
}

class _Boot {
  _Boot(this.ready, this.mode, this.relayUrl, this.torSocks);
  final SendPort ready;
  final String mode;
  final String relayUrl;
  final String torSocks;
}

class _WorkerError {
  _WorkerError(this.message);
  final String message;
}

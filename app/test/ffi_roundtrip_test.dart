// Integration test: drives the real native clarity-core library through the
// same dart:ffi wrapper the app uses — account generation, PQXDH session
// establishment, Double Ratchet messaging, safety numbers, session
// persistence, and the mesh bridge with a loopback radio.
//
// Requires libclarity_ffi.so on the loader path:
//   tool/build_rust.sh linux   (from the repo root)
//   cd app && LD_LIBRARY_PATH=../target/release flutter test
//
// When the library can't be loaded the whole suite is skipped, so plain
// `flutter test` still passes on machines without the native build.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';

import 'package:clarity_messenger/src/ffi/clarity.dart';
import 'package:clarity_messenger/src/ffi/clarity_bindings.dart';
import 'package:clarity_messenger/src/services/mesh_service.dart';

/// A pair of in-memory radios wired to each other, standing in for Bluetooth.
class LoopbackRadio implements MeshRadio {
  LoopbackRadio();

  LoopbackRadio? peer;
  final _incoming = StreamController<Uint8List>.broadcast();

  @override
  Stream<Uint8List> get incomingFrames => _incoming.stream;

  @override
  Future<void> broadcast(List<Uint8List> frames) async {
    final other = peer;
    if (other == null) return;
    for (final frame in frames) {
      other._incoming.add(frame);
    }
  }

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async {
    await _incoming.close();
  }
}

void main() {
  String? skipReason;
  try {
    ClarityBindings.open();
  } catch (_) {
    skipReason = 'libclarity_ffi.so not found — build it with '
        '`tool/build_rust.sh linux` and run tests with '
        'LD_LIBRARY_PATH=../target/release';
  }

  group('native round trip', () {
    late Clarity clarity;

    setUpAll(() {
      clarity = Clarity.instance();
    });

    test('PQXDH handshake and Double Ratchet, both directions', () {
      final alice = clarity.generateAccount();
      final bob = clarity.generateAccount();

      final aliceSession = alice.initiateSession(bob.bundleBase());
      final first = aliceSession.encrypt(utf8Bytes('hello bob'));
      final (bobSession, firstPlain) = bob.respondToSession(first);
      expect(utf8.decode(firstPlain), 'hello bob');

      final reply = bobSession.encrypt(utf8Bytes('hello alice'));
      expect(utf8.decode(aliceSession.decrypt(reply)), 'hello alice');

      for (var i = 0; i < 10; i++) {
        final m = aliceSession.encrypt(utf8Bytes('ping $i'));
        expect(utf8.decode(bobSession.decrypt(m)), 'ping $i');
        final r = bobSession.encrypt(utf8Bytes('pong $i'));
        expect(utf8.decode(aliceSession.decrypt(r)), 'pong $i');
      }

      aliceSession.dispose();
      bobSession.dispose();
      alice.dispose();
      bob.dispose();
    });

    test('malformed bundle is rejected', () {
      final alice = clarity.generateAccount();
      expect(
        () => alice.initiateSession(Uint8List.fromList(List.filled(64, 0xAB))),
        throwsA(isA<ClarityException>()),
      );
      alice.dispose();
    });

    test('safety number is 60 digits and order-independent', () {
      final alice = clarity.generateAccount();
      final bob = clarity.generateAccount();
      final a = alice.identityPublic();
      final b = bob.identityPublic();

      final ab = clarity.safetyNumber(a, b);
      final ba = clarity.safetyNumber(b, a);
      expect(ab, ba);
      expect(ab.replaceAll(RegExp(r'[^0-9]'), '').length, 60);

      alice.dispose();
      bob.dispose();
    });

    test('account and mid-conversation session survive serialize/restore', () {
      final alice = clarity.generateAccount();
      final bob = clarity.generateAccount();

      final restoredAlice = clarity.restoreAccount(alice.serialize());
      expect(restoredAlice.identityPublic(), alice.identityPublic());

      final aliceSession = restoredAlice.initiateSession(bob.bundleBase());
      final (bobSession, _) =
          bob.respondToSession(aliceSession.encrypt(utf8Bytes('start')));
      expect(
        utf8.decode(aliceSession.decrypt(bobSession.encrypt(utf8Bytes('ack')))),
        'ack',
      );

      final resumed = clarity.restoreSession(aliceSession.serialize());
      final m = resumed.encrypt(utf8Bytes('after restore'));
      expect(utf8.decode(bobSession.decrypt(m)), 'after restore');
      final r = bobSession.encrypt(utf8Bytes('still here'));
      expect(utf8.decode(resumed.decrypt(r)), 'still here');

      resumed.dispose();
      aliceSession.dispose();
      bobSession.dispose();
      restoredAlice.dispose();
      alice.dispose();
      bob.dispose();
    });

    test('mesh bridge delivers an end-to-end encrypted payload', () async {
      final alice = clarity.generateAccount();
      final bob = clarity.generateAccount();

      final aliceSession = alice.initiateSession(bob.bundleBase());

      final aliceRadio = LoopbackRadio();
      final bobRadio = LoopbackRadio();
      aliceRadio.peer = bobRadio;
      bobRadio.peer = aliceRadio;

      final aliceMesh = MeshService(aliceRadio, alice.identityPublic());
      final bobMesh = MeshService(bobRadio, bob.identityPublic());
      await aliceMesh.start();
      await bobMesh.start();

      final delivered = bobMesh.inbox.first;
      final wire = aliceSession.encrypt(utf8Bytes('over the mesh'));
      await aliceMesh.send(bob.identityPublic(), wire);

      final payload = await delivered.timeout(const Duration(seconds: 5));
      final (bobSession, plain) = bob.respondToSession(payload);
      expect(utf8.decode(plain), 'over the mesh');

      await aliceMesh.dispose();
      await bobMesh.dispose();
      bobSession.dispose();
      aliceSession.dispose();
      alice.dispose();
      bob.dispose();
    });
  }, skip: skipReason);
}

Uint8List utf8Bytes(String s) => Uint8List.fromList(utf8.encode(s));

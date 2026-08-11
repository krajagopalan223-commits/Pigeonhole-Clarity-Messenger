// Pure-Dart unit tests: UI models, transport config serialization, and the
// FFI byte-list decoder. No native library required.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';

import 'package:clarity_messenger/src/ffi/clarity.dart';
import 'package:clarity_messenger/src/models/models.dart';
import 'package:clarity_messenger/src/services/transport_config.dart';

void main() {
  group('Contact', () {
    test('id is lowercase hex of the identity key', () {
      final identity = Uint8List.fromList(List.generate(32, (i) => i));
      final contact = Contact(identity: identity, displayName: 'A');
      expect(contact.id, hasLength(64));
      expect(contact.id.startsWith('000102030405'), isTrue);
      expect(contact.id, contact.id.toLowerCase());
    });
  });

  group('TransportConfig', () {
    test('JSON round trip preserves every field', () {
      const config = TransportConfig(
        mode: TransportMode.relayTor,
        relayUrl: 'http://example.onion',
        torSocks: '127.0.0.1:9150',
      );
      final restored = TransportConfig.fromJson(config.toJson());
      expect(restored.mode, TransportMode.relayTor);
      expect(restored.relayUrl, 'http://example.onion');
      expect(restored.torSocks, '127.0.0.1:9150');
    });

    test('unknown mode falls back to relayDirect', () {
      final restored = TransportConfig.fromJson({'mode': 'carrier-pigeon'});
      expect(restored.mode, TransportMode.relayDirect);
      expect(restored.relayUrl, 'http://127.0.0.1:8080');
    });

    test('usesRelay is true for both relay modes and false for mesh', () {
      expect(const TransportConfig(mode: TransportMode.relayDirect).usesRelay, isTrue);
      expect(const TransportConfig(mode: TransportMode.relayTor).usesRelay, isTrue);
      expect(const TransportConfig(mode: TransportMode.mesh).usesRelay, isFalse);
    });
  });

  group('decodeByteList', () {
    Uint8List encode(List<List<int>> items) {
      final b = BytesBuilder();
      b.add(_u32(items.length));
      for (final item in items) {
        b.add(_u32(item.length));
        b.add(item);
      }
      return b.toBytes();
    }

    test('decodes an empty buffer to an empty list', () {
      expect(decodeByteList(Uint8List(0)), isEmpty);
      expect(decodeByteList(encode([])), isEmpty);
    });

    test('decodes multiple length-prefixed items', () {
      final decoded = decodeByteList(encode([
        [1, 2, 3],
        [],
        [0xFF],
      ]));
      expect(decoded, hasLength(3));
      expect(decoded[0], [1, 2, 3]);
      expect(decoded[1], isEmpty);
      expect(decoded[2], [0xFF]);
    });
  });
}

Uint8List _u32(int v) {
  final b = ByteData(4)..setUint32(0, v, Endian.little);
  return b.buffer.asUint8List();
}

// Pure-Dart tests for the typed content schema carried inside the encryption.

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';

import 'package:clarity_messenger/src/services/content.dart';

void main() {
  group('MessageContent', () {
    test('text round-trips', () {
      final bytes = const TextContent('hello there').encode();
      final decoded = MessageContent.decode(bytes);
      expect(decoded, isA<TextContent>());
      expect((decoded as TextContent).body, 'hello there');
    });

    test('timer update round-trips, including the cleared state', () {
      final oneDay = MessageContent.decode(const TimerUpdateContent(86400).encode());
      expect((oneDay as TimerUpdateContent).seconds, 86400);

      final cleared = MessageContent.decode(const TimerUpdateContent(null).encode());
      expect((cleared as TimerUpdateContent).seconds, isNull);
    });

    test('plain UTF-8 from a pre-schema client falls back to text', () {
      final decoded = MessageContent.decode(
          Uint8List.fromList(utf8.encode('legacy raw message')));
      expect((decoded as TextContent).body, 'legacy raw message');
    });

    test('non-schema JSON is shown verbatim, not misparsed', () {
      final raw = jsonEncode({'v': 99, 'anything': true});
      final decoded =
          MessageContent.decode(Uint8List.fromList(utf8.encode(raw)));
      expect((decoded as TextContent).body, raw);
    });

    test('a v1 message of an unknown type decodes to UnknownContent', () {
      final raw = jsonEncode({'v': 1, 't': 'hologram', 'data': 'x'});
      expect(MessageContent.decode(Uint8List.fromList(utf8.encode(raw))),
          isA<UnknownContent>());
    });

    test('malformed field types degrade to text instead of throwing', () {
      final raw = jsonEncode({'v': 1, 't': 'timer', 'seconds': 'soon'});
      expect(MessageContent.decode(Uint8List.fromList(utf8.encode(raw))),
          isA<TextContent>());
    });

    test('retention labels', () {
      expect(retentionLabel(null), 'off');
      expect(retentionLabel(3600), '1 hour');
      expect(retentionLabel(86400), '1 day');
      expect(retentionLabel(604800), '1 week');
    });
  });
}

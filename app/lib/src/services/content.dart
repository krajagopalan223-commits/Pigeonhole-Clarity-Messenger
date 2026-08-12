// Typed message content — the small schema carried *inside* the encryption.
//
// The Double Ratchet encrypts opaque bytes; this is what those bytes say. A
// versioned JSON object distinguishes a chat message from in-band control
// traffic (today: disappearing-timer updates), and leaves room for receipts
// and attachments later without another format break.
//
// Wire shape (inside the encryption — transports never see it):
//   {"v": 1, "t": "text",  "body": "..."}
//   {"v": 1, "t": "timer", "seconds": 86400}      // null/absent = keep forever
//
// Decoding is deliberately forgiving:
//   * bytes that don't parse as a v1 object are treated as plain UTF-8 text
//     (messages from clients predating this schema still display), and
//   * a v1 object with an unrecognized "t" decodes to [UnknownContent] so
//     future message types are silently skipped instead of rendered as noise.

import 'dart:convert';
import 'dart:typed_data';

sealed class MessageContent {
  const MessageContent();

  /// Bytes to hand to `Session.encrypt`.
  Uint8List encode();

  /// Interpret decrypted plaintext. Never throws.
  static MessageContent decode(Uint8List plaintext) {
    try {
      final decoded = jsonDecode(utf8.decode(plaintext));
      if (decoded is Map<String, dynamic> && decoded['v'] == 1) {
        switch (decoded['t']) {
          case 'text':
            return TextContent(decoded['body'] as String? ?? '');
          case 'timer':
            return TimerUpdateContent(decoded['seconds'] as int?);
          default:
            return const UnknownContent();
        }
      }
    } on FormatException {
      // Not UTF-8 JSON: fall through to the plain-text path.
    } on TypeError {
      // Right shape, wrong field types: treat as opaque text below.
    }
    return TextContent(utf8.decode(plaintext, allowMalformed: true));
  }
}

/// An ordinary chat message.
class TextContent extends MessageContent {
  const TextContent(this.body);
  final String body;

  @override
  Uint8List encode() =>
      Uint8List.fromList(utf8.encode(jsonEncode({'v': 1, 't': 'text', 'body': body})));
}

/// The sender changed the disappearing-messages timer for this conversation.
class TimerUpdateContent extends MessageContent {
  const TimerUpdateContent(this.seconds);

  /// Retention in seconds; null clears the timer.
  final int? seconds;

  @override
  Uint8List encode() =>
      Uint8List.fromList(utf8.encode(jsonEncode({'v': 1, 't': 'timer', 'seconds': seconds})));
}

/// A v1 message of a type this build doesn't know. Skipped silently.
class UnknownContent extends MessageContent {
  const UnknownContent();

  @override
  Uint8List encode() => throw UnsupportedError('unknown content is receive-only');
}

/// Human-readable label for a retention value, shared by UI and info entries.
String retentionLabel(int? seconds) => switch (seconds) {
      null => 'off',
      3600 => '1 hour',
      86400 => '1 day',
      604800 => '1 week',
      final s => '${Duration(seconds: s)}',
    };

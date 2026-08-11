// Plain data models for the UI layer.

import 'dart:typed_data';

/// A contact the user can message, identified by their 32-byte identity key.
class Contact {
  Contact({required this.identity, required this.displayName, this.verified = false});

  /// 32-byte Ed25519 identity public key.
  final Uint8List identity;
  final String displayName;

  /// Whether the user has confirmed this contact's safety number out-of-band.
  bool verified;

  /// Lowercase hex of the identity, used as a stable map key.
  String get id => identity.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// The direction a message travelled.
enum MessageDirection { incoming, outgoing }

/// A single decrypted message shown in a conversation.
class ChatMessage {
  ChatMessage({
    required this.direction,
    required this.text,
    required this.timestamp,
  });

  final MessageDirection direction;
  final String text;
  final DateTime timestamp;
}

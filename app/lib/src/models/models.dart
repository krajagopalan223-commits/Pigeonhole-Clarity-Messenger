// Plain data models for the UI layer.

import 'dart:typed_data';

/// A contact the user can message, identified by their 32-byte identity key.
class Contact {
  Contact({
    required this.identity,
    required this.identityDh,
    required this.displayName,
    this.verified = false,
  });

  /// 32-byte Ed25519 identity public key.
  final Uint8List identity;

  /// 32-byte X25519 identity DH key — what sealed envelopes to them are
  /// encrypted to. Learned from their verified bundle or their first envelope.
  final Uint8List identityDh;
  final String displayName;

  /// Whether the user has confirmed this contact's safety number out-of-band.
  bool verified;

  /// Disappearing-messages timer for this conversation, in seconds. Messages
  /// older than this are deleted **on this device**; null keeps them forever.
  /// The timer is not (yet) synced to the contact — their copy is theirs.
  int? retentionSeconds;

  /// Lowercase hex of the identity, used as a stable map key.
  String get id => identity.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// The direction a message travelled; [info] is a local status line (e.g. a
/// disappearing-timer change), not something that crossed the wire as chat.
enum MessageDirection { incoming, outgoing, info }

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

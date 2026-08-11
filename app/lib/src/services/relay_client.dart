// HTTP client for the Clarity relay (see the `relay` crate).
//
// The relay only ever sees ciphertext and public keys, so this client speaks in
// opaque byte blobs it gets from the native core. All bodies are JSON with
// base64-encoded binary fields, matching relay/src/protocol.rs.

import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

class RelayClient {
  RelayClient(this.baseUrl, {http.Client? client})
      : _client = client ?? http.Client();

  /// e.g. `https://relay.example.org`. Use HTTPS in production.
  final String baseUrl;
  final http.Client _client;

  /// Upload a base bundle plus the pool of one-time prekeys.
  Future<void> publish(Uint8List baseBundle, List<Map<String, dynamic>> oneTime) async {
    final body = jsonEncode({
      'bundle': base64.encode(baseBundle),
      'one_time': oneTime, // already {id, public(base64)} maps from the core
    });
    final resp = await _client.post(
      Uri.parse('$baseUrl/publish'),
      headers: const {'content-type': 'application/json'},
      body: body,
    );
    _ensureOk(resp, 'publish');
  }

  /// Fetch a contact's prekey bundle (consumes one one-time prekey server-side).
  /// Returns null if the identity is unknown to the relay.
  Future<Uint8List?> fetchBundle(Uint8List identity) async {
    final id = Uri.encodeQueryComponent(base64.encode(identity));
    final resp = await _client.get(Uri.parse('$baseUrl/bundle?identity=$id'));
    if (resp.statusCode == 404) return null;
    _ensureOk(resp, 'fetchBundle');
    final json = jsonDecode(resp.body) as Map<String, dynamic>;
    return base64.decode(json['bundle'] as String);
  }

  /// Queue an encrypted message for a recipient.
  Future<void> send(Uint8List recipient, Uint8List message) async {
    final body = jsonEncode({
      'recipient': base64.encode(recipient),
      'message': base64.encode(message),
    });
    final resp = await _client.post(
      Uri.parse('$baseUrl/send'),
      headers: const {'content-type': 'application/json'},
      body: body,
    );
    _ensureOk(resp, 'send');
  }

  /// Drain queued messages for a recipient (delivery order).
  Future<List<Uint8List>> poll(Uint8List recipient) async {
    final id = Uri.encodeQueryComponent(base64.encode(recipient));
    final resp = await _client.get(Uri.parse('$baseUrl/poll?recipient=$id'));
    _ensureOk(resp, 'poll');
    final json = jsonDecode(resp.body) as Map<String, dynamic>;
    final messages = (json['messages'] as List<dynamic>).cast<String>();
    return messages.map((m) => base64.decode(m)).toList();
  }

  void _ensureOk(http.Response resp, String op) {
    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      throw RelayException('$op failed: HTTP ${resp.statusCode} ${resp.body}');
    }
  }

  void close() => _client.close();
}

class RelayException implements Exception {
  RelayException(this.message);
  final String message;
  @override
  String toString() => 'RelayException: $message';
}

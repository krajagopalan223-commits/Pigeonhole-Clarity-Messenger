// Application state: owns the local account, active sessions, contacts, and the
// polling loop. Bridges the native core (Clarity) and the relay (RelayClient).
//
// Message routing note: the relay routes by recipient identity only, so a
// polled message carries no sender tag the core can read. We wrap each relay
// payload in a small app-level envelope {sender, payload} so the recipient knows
// which session to use. This intentionally exposes the sender identity to the
// relay operator — the same metadata already implied by identity-based routing.
// Reducing that is a transport-layer concern (see ARCHITECTURE.md), not the
// crypto core's job.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../ffi/clarity.dart';
import '../models/models.dart';
import '../services/relay_client.dart';

class AppState extends ChangeNotifier {
  AppState({required String relayUrl, FlutterSecureStorage? storage})
      : _relay = RelayClient(relayUrl),
        _storage = storage ?? const FlutterSecureStorage();

  final Clarity _clarity = Clarity.instance();
  final RelayClient _relay;
  final FlutterSecureStorage _storage;

  static const _accountKey = 'clarity.account.v1';

  Account? _account;
  Uint8List? _myIdentity;
  Timer? _pollTimer;

  final Map<String, Contact> _contacts = {};
  final Map<String, Session> _sessions = {};
  final Map<String, List<ChatMessage>> _conversations = {};

  bool get ready => _account != null;
  Uint8List? get myIdentity => _myIdentity;
  List<Contact> get contacts => _contacts.values.toList();

  List<ChatMessage> conversation(String contactId) =>
      List.unmodifiable(_conversations[contactId] ?? const []);

  /// Load an existing identity or create a new one, then start polling.
  Future<void> initialize() async {
    final stored = await _storage.read(key: _accountKey);
    if (stored != null) {
      _account = _clarity.restoreAccount(base64.decode(stored));
    } else {
      _account = _clarity.generateAccount();
      await _storage.write(key: _accountKey, value: base64.encode(_account!.serialize()));
    }
    _myIdentity = _account!.identityPublic();

    await _publishBundle();
    _startPolling();
    notifyListeners();
  }

  Future<void> _publishBundle() async {
    final account = _account!;
    await _relay.publish(account.bundleBase(), account.oneTimePublics());
  }

  /// Add a contact by their identity key, opening an outgoing session.
  Future<void> addContact(Uint8List identity, String displayName) async {
    final contact = Contact(identity: identity, displayName: displayName);
    final bundle = await _relay.fetchBundle(identity);
    if (bundle == null) {
      throw RelayException('no bundle published for that identity');
    }
    final session = _account!.initiateSession(bundle);
    _contacts[contact.id] = contact;
    _sessions[contact.id] = session;
    _conversations.putIfAbsent(contact.id, () => []);
    notifyListeners();
  }

  /// Send a text message to a contact.
  Future<void> sendMessage(String contactId, String text) async {
    final session = _sessions[contactId];
    final contact = _contacts[contactId];
    if (session == null || contact == null) {
      throw StateError('no session for contact');
    }
    final wire = session.encrypt(Uint8List.fromList(utf8.encode(text)));
    await _relay.send(contact.identity, _wrap(wire));

    _conversations[contactId]!.add(ChatMessage(
      direction: MessageDirection.outgoing,
      text: text,
      timestamp: DateTime.now(),
    ));
    notifyListeners();
  }

  /// The safety number to compare out-of-band with a contact.
  String safetyNumberFor(String contactId) {
    final contact = _contacts[contactId]!;
    return _clarity.safetyNumber(_myIdentity!, contact.identity);
  }

  void markVerified(String contactId) {
    _contacts[contactId]?.verified = true;
    notifyListeners();
  }

  void _startPolling() {
    _pollTimer?.cancel();
    _pollTimer = Timer.periodic(const Duration(seconds: 3), (_) => _pollOnce());
  }

  Future<void> _pollOnce() async {
    if (_myIdentity == null) return;
    final List<Uint8List> inbox;
    try {
      inbox = await _relay.poll(_myIdentity!);
    } catch (_) {
      return; // transient network error; try again next tick
    }
    var changed = false;
    for (final raw in inbox) {
      if (_handleIncoming(raw)) changed = true;
    }
    if (changed) notifyListeners();
  }

  bool _handleIncoming(Uint8List raw) {
    final (senderId, payload) = _unwrap(raw);
    final senderKey = _hex(senderId);
    try {
      final existing = _sessions[senderKey];
      final Uint8List plaintext;
      if (existing != null) {
        plaintext = existing.decrypt(payload);
      } else {
        final (session, first) = _account!.respondToSession(payload);
        _sessions[senderKey] = session;
        _contacts.putIfAbsent(
          senderKey,
          () => Contact(identity: senderId, displayName: _shortId(senderId)),
        );
        _conversations.putIfAbsent(senderKey, () => []);
        plaintext = first;
      }
      _conversations.putIfAbsent(senderKey, () => []).add(ChatMessage(
            direction: MessageDirection.incoming,
            text: utf8.decode(plaintext),
            timestamp: DateTime.now(),
          ));
      return true;
    } on ClarityException {
      // Undecryptable (replay, corruption, or unknown sender state): drop it.
      return false;
    }
  }

  // --- app-level envelope ---------------------------------------------------

  Uint8List _wrap(Uint8List wire) {
    final env = jsonEncode({
      'sender': base64.encode(_myIdentity!),
      'payload': base64.encode(wire),
    });
    return Uint8List.fromList(utf8.encode(env));
  }

  (Uint8List, Uint8List) _unwrap(Uint8List raw) {
    final map = jsonDecode(utf8.decode(raw)) as Map<String, dynamic>;
    final sender = base64.decode(map['sender'] as String);
    final payload = base64.decode(map['payload'] as String);
    return (sender, payload);
  }

  String _hex(Uint8List b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  String _shortId(Uint8List id) => '${_hex(id).substring(0, 8)}…';

  @override
  void dispose() {
    _pollTimer?.cancel();
    for (final s in _sessions.values) {
      s.dispose();
    }
    _account?.dispose();
    _relay.close();
    super.dispose();
  }
}

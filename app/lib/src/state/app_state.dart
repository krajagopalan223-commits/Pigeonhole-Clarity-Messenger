// Application state: owns the local account, sessions, contacts, and the active
// transport (relay/Tor via a worker isolate, or Bluetooth mesh). Persists the
// account, contacts, and live session state so conversations survive restarts.
//
// Routing envelope: transports route by recipient identity only, so each payload
// is wrapped `{sender, payload}` to tell the recipient which session to use. This
// exposes the sender identity to the transport — acceptable given identity-based
// routing; see ARCHITECTURE.md for the metadata-minimization roadmap.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../ffi/clarity.dart';
import '../models/models.dart';
import '../services/mesh_service.dart';
import '../services/relay_worker.dart';
import '../services/transport_config.dart';

class AppState extends ChangeNotifier {
  AppState({
    required TransportConfig config,
    FlutterSecureStorage? storage,
    MeshRadio? meshRadio,
  })  : _config = config,
        _meshRadio = meshRadio,
        _storage = storage ?? const FlutterSecureStorage();

  final Clarity _clarity = Clarity.instance();
  final FlutterSecureStorage _storage;
  final MeshRadio? _meshRadio;

  TransportConfig _config;
  TransportConfig get config => _config;

  static const _accountKey = 'clarity.account.v1';
  static const _contactsKey = 'clarity.contacts.v1';
  static String _sessionKey(String contactId) => 'clarity.session.$contactId.v1';

  Account? _account;
  Uint8List? _myIdentity;

  RelayWorker? _relay;
  MeshService? _mesh;
  Timer? _pollTimer;
  StreamSubscription<Uint8List>? _meshSub;

  final Map<String, Contact> _contacts = {};
  final Map<String, Session> _sessions = {};
  final Map<String, List<ChatMessage>> _conversations = {};

  bool get ready => _account != null;
  Uint8List? get myIdentity => _myIdentity;
  List<Contact> get contacts => _contacts.values.toList();

  List<ChatMessage> conversation(String contactId) =>
      List.unmodifiable(_conversations[contactId] ?? const []);

  /// Load or create the identity, restore saved contacts/sessions, publish, and
  /// start the configured transport.
  Future<void> initialize() async {
    final stored = await _storage.read(key: _accountKey);
    if (stored != null) {
      _account = _clarity.restoreAccount(base64.decode(stored));
    } else {
      _account = _clarity.generateAccount();
      await _storage.write(key: _accountKey, value: base64.encode(_account!.serialize()));
    }
    _myIdentity = _account!.identityPublic();

    await _restoreContactsAndSessions();
    await _startTransport();
    notifyListeners();
  }

  /// Switch transports at runtime (relay/Tor/mesh).
  Future<void> setConfig(TransportConfig config) async {
    _config = config;
    await _stopTransport();
    await _startTransport();
    notifyListeners();
  }

  Future<void> _startTransport() async {
    if (_config.usesRelay) {
      _relay = await RelayWorker.start(_config);
      await _publishBundle();
      _pollTimer = Timer.periodic(const Duration(seconds: 3), (_) => _pollOnce());
    } else if (_config.mode == TransportMode.mesh) {
      final radio = _meshRadio;
      if (radio == null) {
        throw StateError('mesh mode selected but no MeshRadio was provided');
      }
      final mesh = MeshService(radio, _myIdentity!);
      _meshSub = mesh.inbox.listen((payload) {
        if (_handleIncoming(payload)) notifyListeners();
      });
      await mesh.start();
      _mesh = mesh;
    }
  }

  Future<void> _stopTransport() async {
    _pollTimer?.cancel();
    _pollTimer = null;
    _relay?.dispose();
    _relay = null;
    await _meshSub?.cancel();
    _meshSub = null;
    await _mesh?.dispose();
    _mesh = null;
  }

  Future<void> _publishBundle() async {
    final account = _account!;
    final bundle = account.bundleBase();
    final oneTimeJson = Uint8List.fromList(utf8.encode(jsonEncode(account.oneTimePublics())));
    await _relay?.publish(bundle, oneTimeJson);
  }

  /// Add a contact by identity key and open an outgoing session.
  Future<void> addContact(Uint8List identity, String displayName) async {
    final contact = Contact(identity: identity, displayName: displayName);
    final bundle = await _fetchBundle(identity);
    if (bundle == null) {
      throw StateError('no prekey bundle available for that identity');
    }
    final session = _account!.initiateSession(bundle);
    _contacts[contact.id] = contact;
    _sessions[contact.id] = session;
    _conversations.putIfAbsent(contact.id, () => []);
    await _persistSession(contact.id);
    await _persistContacts();
    notifyListeners();
  }

  Future<Uint8List?> _fetchBundle(Uint8List identity) async {
    if (_relay != null) return _relay!.fetchBundle(identity);
    // In pure-mesh mode bundles are exchanged on contact; not via a directory.
    throw StateError('bundle fetch requires a relay transport');
  }

  /// Send a text message to a contact.
  Future<void> sendMessage(String contactId, String text) async {
    final session = _sessions[contactId];
    final contact = _contacts[contactId];
    if (session == null || contact == null) {
      throw StateError('no session for contact');
    }
    final wire = session.encrypt(Uint8List.fromList(utf8.encode(text)));
    final envelope = _wrap(wire);
    await _transportSend(contact.identity, envelope);

    _conversations[contactId]!.add(ChatMessage(
      direction: MessageDirection.outgoing,
      text: text,
      timestamp: DateTime.now(),
    ));
    await _persistSession(contactId); // ratchet advanced
    notifyListeners();
  }

  Future<void> _transportSend(Uint8List recipient, Uint8List payload) async {
    if (_relay != null) {
      await _relay!.send(recipient, payload);
    } else if (_mesh != null) {
      await _mesh!.send(recipient, payload);
    } else {
      throw StateError('no active transport');
    }
  }

  String safetyNumberFor(String contactId) {
    final contact = _contacts[contactId]!;
    return _clarity.safetyNumber(_myIdentity!, contact.identity);
  }

  Future<void> markVerified(String contactId) async {
    _contacts[contactId]?.verified = true;
    await _persistContacts();
    notifyListeners();
  }

  // --- inbound handling ------------------------------------------------------

  Future<void> _pollOnce() async {
    final relay = _relay;
    final me = _myIdentity;
    if (relay == null || me == null) return;
    final Uint8List raw;
    try {
      raw = await relay.poll(me);
    } catch (_) {
      return; // transient; retry next tick
    }
    var changed = false;
    for (final envelope in decodeByteList(raw)) {
      if (_handleIncoming(envelope)) changed = true;
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
      // Persist advanced session + possibly-new contact (fire and forget).
      unawaited(_persistSession(senderKey));
      unawaited(_persistContacts());
      return true;
    } on ClarityException {
      return false; // undecryptable: drop
    }
  }

  // --- persistence -----------------------------------------------------------

  Future<void> _persistSession(String contactId) async {
    final session = _sessions[contactId];
    if (session == null) return;
    await _storage.write(
      key: _sessionKey(contactId),
      value: base64.encode(session.serialize()),
    );
  }

  Future<void> _persistContacts() async {
    final list = _contacts.values
        .map((c) => {
              'identity': base64.encode(c.identity),
              'name': c.displayName,
              'verified': c.verified,
            })
        .toList();
    await _storage.write(key: _contactsKey, value: jsonEncode(list));
  }

  Future<void> _restoreContactsAndSessions() async {
    final contactsRaw = await _storage.read(key: _contactsKey);
    if (contactsRaw == null) return;
    final list = (jsonDecode(contactsRaw) as List<dynamic>).cast<Map<String, dynamic>>();
    for (final entry in list) {
      final identity = Uint8List.fromList(base64.decode(entry['identity'] as String));
      final contact = Contact(
        identity: identity,
        displayName: entry['name'] as String,
        verified: entry['verified'] as bool? ?? false,
      );
      _contacts[contact.id] = contact;
      _conversations.putIfAbsent(contact.id, () => []);

      final sessionRaw = await _storage.read(key: _sessionKey(contact.id));
      if (sessionRaw != null) {
        try {
          _sessions[contact.id] = _clarity.restoreSession(base64.decode(sessionRaw));
        } on ClarityException {
          // Corrupt/incompatible saved session: it will re-establish on next contact.
        }
      }
    }
  }

  // --- envelope + helpers ----------------------------------------------------

  Uint8List _wrap(Uint8List wire) {
    final env = jsonEncode({
      'sender': base64.encode(_myIdentity!),
      'payload': base64.encode(wire),
    });
    return Uint8List.fromList(utf8.encode(env));
  }

  (Uint8List, Uint8List) _unwrap(Uint8List raw) {
    final map = jsonDecode(utf8.decode(raw)) as Map<String, dynamic>;
    return (
      Uint8List.fromList(base64.decode(map['sender'] as String)),
      Uint8List.fromList(base64.decode(map['payload'] as String)),
    );
  }

  String _hex(Uint8List b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
  String _shortId(Uint8List id) => '${_hex(id).substring(0, 8)}…';

  @override
  void dispose() {
    _stopTransport();
    for (final s in _sessions.values) {
      s.dispose();
    }
    _account?.dispose();
    super.dispose();
  }
}

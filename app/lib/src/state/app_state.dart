// Application state: owns the local account, sessions, contacts, and the active
// transport (relay/Tor via a worker isolate, or Bluetooth mesh). Persists the
// account, contacts, and live session state so conversations survive restarts.
//
// Metadata: every payload travels inside a sealed-sender envelope (the sender
// identity is inside the encryption, not beside it), and relay mail is
// addressed to rotating inbox IDs instead of identity keys — so the relay sees
// neither who sent a message nor a stable identifier for who receives it. The
// mesh still routes by recipient identity (its radio broadcasts presence
// anyway), but couriers carry the same sealed envelopes. See ARCHITECTURE.md.

import 'dart:async';
import 'dart:convert';

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
  // v2: contact entries carry the X25519 identity-DH (sealing) key. v1 data
  // (pre-sealed-sender) is simply ignored; this is a pre-release format bump.
  static const _contactsKey = 'clarity.contacts.v2';
  static const _lastPollEpochKey = 'clarity.lastPollEpoch.v1';
  static String _sessionKey(String contactId) => 'clarity.session.$contactId.v1';

  /// Widest catch-up window of rotating inboxes polled in one tick (30 days'
  /// worth); mail parked under inboxes older than the window is left behind.
  static const _maxPollEpochs = 30;

  Account? _account;
  Uint8List? _myIdentity;
  int? _lastPollEpoch;

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
    final bundle = await _fetchBundle(identity);
    if (bundle == null) {
      throw StateError('no prekey bundle available for that identity');
    }
    // Verify the bundle's signatures AND that it belongs to the identity that
    // was asked for — a hostile directory must not be able to answer a lookup
    // for Bob with a (validly self-signed) bundle for Mallory.
    final keys = _clarity.bundleIdentityKeys(bundle);
    if (!listEquals(keys.identityEd, identity)) {
      throw StateError('directory returned a bundle for a different identity');
    }
    final session = _account!.initiateSession(bundle);
    final contact = Contact(
      identity: identity,
      identityDh: keys.identityDh,
      displayName: displayName,
    );
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
    final envelope = _account!.sealEnvelope(contact.identityDh, wire);
    await _transportSend(contact, envelope);

    _conversations[contactId]!.add(ChatMessage(
      direction: MessageDirection.outgoing,
      text: text,
      timestamp: DateTime.now(),
    ));
    await _persistSession(contactId); // ratchet advanced
    notifyListeners();
  }

  Future<void> _transportSend(Contact contact, Uint8List sealed) async {
    if (_relay != null) {
      // Relay mail is addressed to the contact's rotating inbox, never their
      // identity; their poll window absorbs clock skew across the boundary.
      final inbox = _clarity.inboxId(contact.identity, _currentEpoch());
      await _relay!.send(inbox, sealed);
    } else if (_mesh != null) {
      await _mesh!.send(contact.identity, sealed);
    } else {
      throw StateError('no active transport');
    }
  }

  int _currentEpoch() =>
      _clarity.epochForUnix(DateTime.now().millisecondsSinceEpoch ~/ 1000);

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

    // Poll a window of rotating inboxes: from just before the last successful
    // poll (or yesterday, on first run) through tomorrow, so an epoch rollover
    // or a skewed sender clock never strands mail.
    final current = _currentEpoch();
    var from = (_lastPollEpoch ?? current) - 1;
    if (from < 0) from = 0;
    if (current + 1 - from >= _maxPollEpochs) from = current + 1 - _maxPollEpochs;
    final inboxes = [
      for (var epoch = from; epoch <= current + 1; epoch++) _clarity.inboxId(me, epoch),
    ];

    final List<Uint8List> envelopes;
    try {
      envelopes = await relay.pollMany(inboxes);
    } catch (_) {
      return; // transient; retry next tick
    }
    if (_lastPollEpoch != current) {
      _lastPollEpoch = current;
      unawaited(_storage.write(key: _lastPollEpochKey, value: current.toString()));
    }
    var changed = false;
    for (final envelope in envelopes) {
      if (_handleIncoming(envelope)) changed = true;
    }
    if (changed) notifyListeners();
  }

  bool _handleIncoming(Uint8List raw) {
    try {
      final opened = _account!.openEnvelope(raw);
      final senderId = opened.senderIdentityEd;
      final senderKey = _hex(senderId);
      final existing = _sessions[senderKey];
      final Uint8List plaintext;
      if (existing != null) {
        plaintext = existing.decrypt(opened.payload);
      } else {
        // The claimed sender is authenticated here: only the real holder of
        // these identity keys produces a handshake that completes.
        final (session, first) = _account!.respondToSession(opened.payload);
        _sessions[senderKey] = session;
        _contacts.putIfAbsent(
          senderKey,
          () => Contact(
            identity: senderId,
            identityDh: opened.senderIdentityDh,
            displayName: _shortId(senderId),
          ),
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
      return false; // not for us, tampered, or a forged sender claim: drop
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
              'identityDh': base64.encode(c.identityDh),
              'name': c.displayName,
              'verified': c.verified,
            })
        .toList();
    await _storage.write(key: _contactsKey, value: jsonEncode(list));
  }

  Future<void> _restoreContactsAndSessions() async {
    final lastPoll = await _storage.read(key: _lastPollEpochKey);
    _lastPollEpoch = lastPoll == null ? null : int.tryParse(lastPoll);

    final contactsRaw = await _storage.read(key: _contactsKey);
    if (contactsRaw == null) return;
    final list = (jsonDecode(contactsRaw) as List<dynamic>).cast<Map<String, dynamic>>();
    for (final entry in list) {
      final identity = Uint8List.fromList(base64.decode(entry['identity'] as String));
      final contact = Contact(
        identity: identity,
        identityDh: Uint8List.fromList(base64.decode(entry['identityDh'] as String)),
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

  // --- helpers ---------------------------------------------------------------

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

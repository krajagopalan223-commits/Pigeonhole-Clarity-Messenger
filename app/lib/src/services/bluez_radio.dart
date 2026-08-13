// BlueZ Bluetooth radio for the mesh — the Linux implementation of [MeshRadio].
//
// Every node plays both BLE roles at once over the BlueZ D-Bus API:
//
//  * **Peripheral** — registers a GATT service with a single write-only "RX"
//    characteristic and an LE advertisement carrying the Clarity service UUID,
//    so nearby nodes can find us and write frames to us.
//  * **Central** — scans for that same service UUID, connects to every peer it
//    finds, and writes outbound frames to *their* RX characteristic.
//
// Mesh frames (padded end-to-end-encrypted payloads, routinely kilobytes) far
// exceed a single BLE write, so each link carries a byte stream of
// `[u32-le length][frame]` records, sliced into MTU-sized chunks. ATT writes
// with type `request` are acknowledged and ordered, which is exactly the
// guarantee the stream framing needs; the receiver reassembles per sender and
// resets that sender's buffer on disconnect, so a torn stream can never
// desynchronize a later session. Duplicate delivery (two nodes connected in
// both directions see every frame twice) is harmless: the routing layer dedups
// by `msg_id`.
//
// Requires bluetoothd and a BLE-capable adapter. Pure Dart (`package:dbus`) —
// no native plugin. Verified against the D-Bus API contract and unit-tested at
// the framing layer; see MESH.md for what still needs real-radio validation.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:dbus/dbus.dart';

import 'mesh_service.dart';

/// The Clarity mesh GATT service, advertised so peers can find each other.
const String clarityMeshServiceUuid = '5eb1f7a4-9d2c-4e0b-8a63-c58d3e100c1a';

/// The write-only characteristic peers write frame chunks to.
const String clarityMeshRxCharUuid = '5eb1f7a4-9d2c-4e0b-8a63-c58d3e100c1b';

/// Chunk size for characteristic writes. Fits a common 247-byte ATT MTU;
/// BlueZ transparently falls back to prepared (long) writes on smaller MTUs.
const int meshChunkSize = 244;

/// Upper bound on a single mesh frame arriving over a link. Generous versus
/// the 8 KiB padding buckets; anything larger is a protocol violation.
const int meshMaxFrameLength = 128 * 1024;

/// Thrown by [FrameAssembler] when a link's byte stream is malformed.
class FrameProtocolException implements Exception {
  const FrameProtocolException(this.message);
  final String message;
  @override
  String toString() => 'FrameProtocolException: $message';
}

/// Slice `[u32-le length][frame]` records into chunks of at most [chunkSize].
///
/// The concatenation of the returned chunks is the canonical stream encoding
/// of [frames], so the same chunk list can be written to every link — provided
/// each link always receives whole calls' worth of chunks, in order.
List<Uint8List> chunkFrames(List<Uint8List> frames, {int chunkSize = meshChunkSize}) {
  if (chunkSize <= 0) throw ArgumentError.value(chunkSize, 'chunkSize');
  final stream = BytesBuilder(copy: false);
  for (final frame in frames) {
    final header = ByteData(4)..setUint32(0, frame.length, Endian.little);
    stream.add(header.buffer.asUint8List());
    stream.add(frame);
  }
  final bytes = stream.takeBytes();
  final chunks = <Uint8List>[];
  for (var i = 0; i < bytes.length; i += chunkSize) {
    final end = (i + chunkSize < bytes.length) ? i + chunkSize : bytes.length;
    chunks.add(Uint8List.sublistView(bytes, i, end));
  }
  return chunks;
}

/// Reassembles the `[u32-le length][frame]` stream for one inbound link.
///
/// Feed every received chunk to [add]; it returns the frames completed so far.
/// A zero or oversized length means the stream is corrupt — the assembler
/// throws and the caller must discard it (there is no way to resynchronize a
/// length-prefixed stream).
class FrameAssembler {
  final _pending = BytesBuilder(copy: true);

  List<Uint8List> add(Uint8List chunk) {
    _pending.add(chunk);
    var bytes = _pending.takeBytes();
    final frames = <Uint8List>[];
    var offset = 0;
    while (bytes.length - offset >= 4) {
      final len = ByteData.sublistView(bytes, offset, offset + 4).getUint32(0, Endian.little);
      if (len == 0 || len > meshMaxFrameLength) {
        throw FrameProtocolException('bad frame length $len');
      }
      if (bytes.length - offset - 4 < len) break;
      frames.add(Uint8List.fromList(bytes.sublist(offset + 4, offset + 4 + len)));
      offset += 4 + len;
    }
    _pending.add(Uint8List.sublistView(bytes, offset));
    return frames;
  }

  /// Bytes buffered awaiting the rest of a frame.
  int get pendingLength => _pending.length;
}

// --- D-Bus glue -------------------------------------------------------------

const _bluezBus = 'org.bluez';
const _adapterIface = 'org.bluez.Adapter1';
const _deviceIface = 'org.bluez.Device1';
const _gattCharIface = 'org.bluez.GattCharacteristic1';
const _gattServiceIface = 'org.bluez.GattService1';
const _gattManagerIface = 'org.bluez.GattManager1';
const _advManagerIface = 'org.bluez.LEAdvertisingManager1';
const _advIface = 'org.bluez.LEAdvertisement1';

final _appPath = DBusObjectPath('/org/clarity/mesh');
final _servicePath = DBusObjectPath('/org/clarity/mesh/service0');
final _charPath = DBusObjectPath('/org/clarity/mesh/service0/char0');
final _advPath = DBusObjectPath('/org/clarity/mesh/advertisement0');

/// An exported object whose properties are a static map — enough for the GATT
/// service/characteristic/advertisement descriptions BlueZ reads back.
class _StaticObject extends DBusObject {
  _StaticObject(super.path, this._interfaces);
  final Map<String, Map<String, DBusValue>> _interfaces;

  @override
  Map<String, Map<String, DBusValue>> get interfacesAndProperties => _interfaces;

  @override
  Future<DBusMethodResponse> getProperty(String interface, String name) async {
    final value = _interfaces[interface]?[name];
    if (value == null) return DBusMethodErrorResponse.unknownProperty();
    return DBusGetPropertyResponse(value);
  }

  @override
  Future<DBusMethodResponse> getAllProperties(String interface) async {
    return DBusGetAllPropertiesResponse(_interfaces[interface] ?? {});
  }
}

/// The RX characteristic: peers write frame chunks here.
class _RxCharacteristic extends _StaticObject {
  _RxCharacteristic(this._onWrite)
      : super(_charPath, {
          _gattCharIface: {
            'UUID': const DBusString(clarityMeshRxCharUuid),
            'Service': _servicePath,
            'Flags': DBusArray.string(const ['write', 'write-without-response']),
          },
        });

  final void Function(String devicePath, Uint8List chunk) _onWrite;

  @override
  Future<DBusMethodResponse> handleMethodCall(DBusMethodCall methodCall) async {
    if (methodCall.interface != _gattCharIface) {
      return DBusMethodErrorResponse.unknownInterface();
    }
    if (methodCall.name != 'WriteValue') {
      return DBusMethodErrorResponse.unknownMethod();
    }
    final chunk = Uint8List.fromList(methodCall.values[0].asByteArray().toList());
    final options = methodCall.values[1].asStringVariantDict();
    final device = options['device'];
    final sender = device is DBusObjectPath ? device.value : '<unknown>';
    _onWrite(sender, chunk);
    return DBusMethodSuccessResponse();
  }
}

/// The LE advertisement announcing the mesh service.
class _Advertisement extends _StaticObject {
  _Advertisement()
      : super(_advPath, {
          _advIface: {
            'Type': const DBusString('peripheral'),
            'ServiceUUIDs': DBusArray.string(const [clarityMeshServiceUuid]),
            'LocalName': const DBusString('Clarity'),
          },
        });

  @override
  Future<DBusMethodResponse> handleMethodCall(DBusMethodCall methodCall) async {
    if (methodCall.interface == _advIface && methodCall.name == 'Release') {
      return DBusMethodSuccessResponse();
    }
    return DBusMethodErrorResponse.unknownMethod();
  }
}

/// One connected peer we can write to: their RX characteristic plus a queue
/// that keeps writes ordered (the stream framing depends on order).
class _Peer {
  _Peer(this.characteristic);
  final DBusRemoteObject characteristic;
  Future<void> writes = Future.value();
}

/// [MeshRadio] over BlueZ, for Linux desktop.
///
/// Restartable: the app holds one instance across transport switches and
/// calls [start]/[stop] each time mesh mode is entered/left, so every [start]
/// opens a fresh bus connection and [stop] tears everything down.
class BlueZMeshRadio implements MeshRadio {
  /// [busFactory] is injectable for tests; defaults to the system bus where
  /// bluetoothd lives.
  BlueZMeshRadio({DBusClient Function()? busFactory})
      : _busFactory = busFactory ?? DBusClient.system;

  final DBusClient Function() _busFactory;
  DBusClient? _busOrNull;
  DBusClient get _bus => _busOrNull ?? (throw StateError('radio not started'));
  DBusRemoteObjectManager? _bluezOrNull;
  DBusRemoteObjectManager get _bluez =>
      _bluezOrNull ?? (throw StateError('radio not started'));

  // Never closed: the radio outlives individual start/stop cycles and
  // MeshService manages its own subscription lifetime.
  final _incoming = StreamController<Uint8List>.broadcast();
  StreamSubscription<DBusSignal>? _signals;
  Timer? _connectSweep;

  DBusObjectPath? _adapterPath;
  final List<DBusObject> _exported = [];
  bool _advertising = false;
  bool _stopped = false;

  /// Devices advertising the mesh service, by object path.
  final Set<String> _known = {};

  /// Devices with a Connect() in flight, to avoid stacking attempts.
  final Set<String> _connecting = {};

  /// Connected peers we can write to, by device path.
  final Map<String, _Peer> _peers = {};

  /// Inbound stream reassembly, by writing device path.
  final Map<String, FrameAssembler> _assemblers = {};

  @override
  Stream<Uint8List> get incomingFrames => _incoming.stream;

  /// Device paths of peers currently writable. Exposed for the UI/status.
  List<String> get connectedPeers => List.unmodifiable(_peers.keys);

  @override
  Future<void> start() async {
    _stopped = false;
    _busOrNull = _busFactory();
    _bluezOrNull =
        DBusRemoteObjectManager(_bus, name: _bluezBus, path: DBusObjectPath('/'));
    final objects = await _bluez.getManagedObjects();

    final adapter = _findAdapter(objects);
    if (adapter == null) {
      throw StateError(
          'no Bluetooth adapter found — is bluetoothd running and an adapter present?');
    }
    _adapterPath = adapter;
    final adapterObj = DBusRemoteObject(_bus, name: _bluezBus, path: adapter);
    await adapterObj.setProperty(_adapterIface, 'Powered', const DBusBoolean(true));

    await _registerGattApplication(adapterObj);
    await _registerAdvertisement(adapterObj);

    _signals = _bluez.signals.listen(_onBluezSignal);

    // Scan for peers advertising the mesh service.
    await adapterObj.callMethod(
        _adapterIface,
        'SetDiscoveryFilter',
        [
          DBusDict.stringVariant({
            'UUIDs': DBusArray.string(const [clarityMeshServiceUuid]),
            'Transport': const DBusString('le'),
            'DuplicateData': const DBusBoolean(false),
          })
        ],
        replySignature: DBusSignature(''));
    await adapterObj.callMethod(_adapterIface, 'StartDiscovery', [],
        replySignature: DBusSignature(''));

    // Adopt devices BlueZ already knows about (paired or still cached).
    objects.forEach((path, interfaces) {
      final device = interfaces[_deviceIface];
      if (device != null) _considerDevice(path.value, device);
    });

    // Periodically retry peers that are in range but not yet connected.
    _connectSweep = Timer.periodic(const Duration(seconds: 10), (_) {
      for (final path in _known.difference(_peers.keys.toSet())) {
        unawaited(_tryConnect(path));
      }
    });
  }

  @override
  Future<void> broadcast(List<Uint8List> frames) async {
    if (frames.isEmpty || _peers.isEmpty) return;
    final chunks = chunkFrames(frames);
    // One ordered write queue per peer; a failed write drops the peer (it will
    // be rediscovered), and the receiver's per-device reset keeps torn streams
    // from corrupting a future session.
    await Future.wait(_peers.entries.toList().map((entry) {
      final path = entry.key;
      final peer = entry.value;
      peer.writes = peer.writes.then((_) async {
        for (final chunk in chunks) {
          await peer.characteristic.callMethod(
              _gattCharIface,
              'WriteValue',
              [
                DBusArray.byte(chunk),
                DBusDict.stringVariant({'type': const DBusString('request')}),
              ],
              replySignature: DBusSignature(''));
        }
      }).catchError((Object e) {
        _peers.remove(path);
      });
      return peer.writes;
    }));
  }

  @override
  Future<void> stop() async {
    _stopped = true;
    _connectSweep?.cancel();
    await _signals?.cancel();

    final adapter = _adapterPath;
    if (adapter != null) {
      final adapterObj = DBusRemoteObject(_bus, name: _bluezBus, path: adapter);
      Future<void> tryCall(String iface, String method, [List<DBusValue> args = const []]) async {
        try {
          await adapterObj.callMethod(iface, method, args, replySignature: DBusSignature(''));
        } on Object {
          // Best-effort teardown: bluetoothd may already have cleaned up.
        }
      }

      await tryCall(_adapterIface, 'StopDiscovery');
      if (_advertising) {
        await tryCall(_advManagerIface, 'UnregisterAdvertisement', [_advPath]);
      }
      await tryCall(_gattManagerIface, 'UnregisterApplication', [_appPath]);
    }
    for (final object in _exported) {
      try {
        await _bus.unregisterObject(object);
      } on Object {
        // Already gone.
      }
    }
    _exported.clear();
    _peers.clear();
    _assemblers.clear();
    _known.clear();
    _connecting.clear();
    _adapterPath = null;
    _advertising = false;
    await _busOrNull?.close();
    _busOrNull = null;
    _bluezOrNull = null;
  }

  // --- peripheral role -------------------------------------------------------

  Future<void> _registerGattApplication(DBusRemoteObject adapter) async {
    final root = DBusObject(_appPath, isObjectManager: true);
    final service = _StaticObject(_servicePath, {
      _gattServiceIface: {
        'UUID': const DBusString(clarityMeshServiceUuid),
        'Primary': const DBusBoolean(true),
      },
    });
    final characteristic = _RxCharacteristic(_onPeerWrite);
    for (final object in [root, service, characteristic]) {
      await _bus.registerObject(object);
      _exported.add(object);
    }
    await adapter.callMethod(_gattManagerIface, 'RegisterApplication',
        [_appPath, DBusDict.stringVariant(const {})],
        replySignature: DBusSignature(''));
  }

  Future<void> _registerAdvertisement(DBusRemoteObject adapter) async {
    final advertisement = _Advertisement();
    await _bus.registerObject(advertisement);
    _exported.add(advertisement);
    try {
      await adapter.callMethod(_advManagerIface, 'RegisterAdvertisement',
          [_advPath, DBusDict.stringVariant(const {})],
          replySignature: DBusSignature(''));
      _advertising = true;
    } on Object catch (e) {
      // Without an advertisement peers cannot find (and write to) us, but we
      // can still discover them and send — degrade rather than die.
      stderr.writeln('clarity mesh: LE advertising unavailable ($e); '
          'this node can send but will not be discovered');
    }
  }

  void _onPeerWrite(String devicePath, Uint8List chunk) {
    final assembler = _assemblers.putIfAbsent(devicePath, FrameAssembler.new);
    List<Uint8List> frames;
    try {
      frames = assembler.add(chunk);
    } on FrameProtocolException {
      // Corrupt stream — discard and start clean on the peer's next write.
      _assemblers.remove(devicePath);
      return;
    }
    frames.forEach(_incoming.add);
  }

  // --- central role ----------------------------------------------------------

  DBusObjectPath? _findAdapter(Map<DBusObjectPath, Map<String, Map<String, DBusValue>>> objects) {
    for (final entry in objects.entries) {
      if (entry.value.containsKey(_adapterIface)) return entry.key;
    }
    return null;
  }

  void _onBluezSignal(DBusSignal signal) {
    if (_stopped) return;
    if (signal is DBusObjectManagerInterfacesAddedSignal) {
      final device = signal.interfacesAndProperties[_deviceIface];
      if (device != null) _considerDevice(signal.changedPath.value, device);
      // A characteristic appearing may complete a pending connection.
      if (signal.interfacesAndProperties.containsKey(_gattCharIface)) {
        final owner = _deviceOf(signal.changedPath.value);
        if (owner != null && _known.contains(owner) && !_peers.containsKey(owner)) {
          unawaited(_resolveCharacteristic(owner));
        }
      }
    } else if (signal is DBusObjectManagerInterfacesRemovedSignal) {
      final path = signal.changedPath.value;
      if (signal.interfaces.contains(_deviceIface)) _forgetDevice(path);
    } else if (signal is DBusPropertiesChangedSignal) {
      if (signal.propertiesInterface != _deviceIface) return;
      final path = signal.path.value;
      final changed = signal.changedProperties;
      final connected = changed['Connected'];
      if (connected is DBusBoolean && !connected.value) {
        // The link died: drop the writable peer and any half-received stream.
        _peers.remove(path);
        _assemblers.remove(path);
      }
      final resolved = changed['ServicesResolved'];
      if (resolved is DBusBoolean && resolved.value && _known.contains(path)) {
        unawaited(_resolveCharacteristic(path));
      }
      final uuids = changed['UUIDs'];
      if (uuids is DBusArray) _considerDevice(path, {'UUIDs': uuids});
    }
  }

  void _considerDevice(String path, Map<String, DBusValue> properties) {
    final uuids = properties['UUIDs'];
    if (uuids is! DBusArray) return;
    final hasService = uuids
        .asStringArray()
        .any((u) => u.toLowerCase() == clarityMeshServiceUuid);
    if (!hasService) return;
    if (!_known.add(path)) return; // already known
    unawaited(_tryConnect(path));
  }

  void _forgetDevice(String path) {
    _known.remove(path);
    _connecting.remove(path);
    _peers.remove(path);
    _assemblers.remove(path);
  }

  Future<void> _tryConnect(String path) async {
    if (_stopped || _peers.containsKey(path) || !_connecting.add(path)) return;
    try {
      final device = DBusRemoteObject(_bus, name: _bluezBus, path: DBusObjectPath(path));
      try {
        await device.callMethod(_deviceIface, 'Connect', [],
            replySignature: DBusSignature(''));
      } on DBusMethodResponseException catch (e) {
        // "Already connected" is success; anything else waits for the sweep.
        if (e.errorName != 'org.bluez.Error.AlreadyConnected') return;
      }
      final resolved = await device.getProperty(_deviceIface, 'ServicesResolved');
      if (resolved is DBusBoolean && resolved.value) {
        await _resolveCharacteristic(path);
      }
      // Otherwise the ServicesResolved property change completes the setup.
    } on Object {
      // Radio-level connect failures are routine (peer moved away); the
      // periodic sweep retries while the device is still in range.
    } finally {
      _connecting.remove(path);
    }
  }

  /// Find the peer's RX characteristic under their device path and start
  /// treating them as writable.
  Future<void> _resolveCharacteristic(String devicePath) async {
    if (_stopped || _peers.containsKey(devicePath)) return;
    final objects = await _bluez.getManagedObjects();
    for (final entry in objects.entries) {
      final path = entry.key.value;
      if (!path.startsWith('$devicePath/')) continue;
      final char = entry.value[_gattCharIface];
      if (char == null) continue;
      final uuid = char['UUID'];
      if (uuid is DBusString && uuid.value.toLowerCase() == clarityMeshRxCharUuid) {
        _peers[devicePath] =
            _Peer(DBusRemoteObject(_bus, name: _bluezBus, path: entry.key));
        return;
      }
    }
  }

  /// `/org/bluez/hciX/dev_XX/serviceYY/charZZ` → `/org/bluez/hciX/dev_XX`.
  String? _deviceOf(String path) {
    final match = RegExp(r'^(/org/bluez/[^/]+/dev_[^/]+)/').firstMatch(path);
    return match?.group(1);
  }
}

// BlueZ mesh radio tests.
//
// Two layers:
//  1. Pure framing — the `[u32-le length][frame]` chunk/reassemble protocol
//     every link speaks. No I/O.
//  2. The radio against a mock bluetoothd: a private D-Bus server where a fake
//     `org.bluez` implements the same object tree, calls, and signals the real
//     daemon does. This proves the D-Bus contract end to end — adapter setup,
//     GATT registration, discovery, connect, chunked writes out, reassembled
//     frames in, disconnect resets, and stop/restart — everything except the
//     radio waves themselves (see MESH.md for what needs real hardware).

import 'dart:io';
import 'dart:typed_data';

import 'package:dbus/dbus.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:clarity_messenger/src/services/bluez_radio.dart';

Uint8List bytesOf(List<int> data) => Uint8List.fromList(data);

Uint8List patterned(int length, [int seed = 7]) =>
    Uint8List.fromList(List.generate(length, (i) => (i * 31 + seed) & 0xFF));

void main() {
  group('frame stream codec', () {
    test('single frame round-trips through chunks', () {
      final frame = patterned(100);
      final chunks = chunkFrames([frame], chunkSize: 24);
      for (final chunk in chunks) {
        expect(chunk.length, lessThanOrEqualTo(24));
      }
      final assembler = FrameAssembler();
      final got = <Uint8List>[];
      for (final chunk in chunks) {
        got.addAll(assembler.add(chunk));
      }
      expect(got, [frame]);
      expect(assembler.pendingLength, 0);
    });

    test('multiple frames, one spanning many chunks, byte-at-a-time', () {
      final frames = [patterned(3), patterned(8192, 11), patterned(1, 13)];
      final chunks = chunkFrames(frames);
      // Worst-case link: every chunk re-split into single bytes.
      final assembler = FrameAssembler();
      final got = <Uint8List>[];
      for (final chunk in chunks) {
        for (final byte in chunk) {
          got.addAll(assembler.add(bytesOf([byte])));
        }
      }
      expect(got.length, 3);
      for (var i = 0; i < 3; i++) {
        expect(got[i], frames[i]);
      }
    });

    test('frames split across broadcast calls stay aligned', () {
      final a = patterned(500, 1);
      final b = patterned(600, 2);
      final assembler = FrameAssembler();
      final got = <Uint8List>[];
      for (final chunk in chunkFrames([a])) {
        got.addAll(assembler.add(chunk));
      }
      for (final chunk in chunkFrames([b])) {
        got.addAll(assembler.add(chunk));
      }
      expect(got, [a, b]);
    });

    test('zero and oversized lengths are protocol violations', () {
      expect(
        () => FrameAssembler().add(bytesOf([0, 0, 0, 0, 1, 2, 3])),
        throwsA(isA<FrameProtocolException>()),
      );
      final huge = ByteData(4)..setUint32(0, meshMaxFrameLength + 1, Endian.little);
      expect(
        () => FrameAssembler().add(huge.buffer.asUint8List()),
        throwsA(isA<FrameProtocolException>()),
      );
    });

    test('chunk concatenation is the canonical stream encoding', () {
      final frames = [patterned(10), patterned(300)];
      final one = chunkFrames(frames, chunkSize: 1 << 30);
      expect(one.length, 1);
      final sliced = chunkFrames(frames, chunkSize: 7);
      final rejoined = BytesBuilder();
      sliced.forEach(rejoined.add);
      expect(rejoined.takeBytes(), one.single);
    });
  });

  group('radio against mock bluetoothd', () {
    late DBusServer server;
    late DBusAddress address;
    late DBusClient bluezClient;
    late MockBluez bluez;
    late BlueZMeshRadio radio;

    setUp(() async {
      server = DBusServer();
      address = await server.listenAddress(DBusAddress.unix(dir: Directory.systemTemp));
      bluezClient = DBusClient(address);
      bluez = MockBluez(bluezClient);
      await bluez.claim();
      radio = BlueZMeshRadio(busFactory: () => DBusClient(address));
    });

    tearDown(() async {
      await bluezClient.close();
      await server.close();
    });

    test('start powers the adapter, registers GATT + advertisement, scans',
        () async {
      await radio.start();

      expect(bluez.adapter.powered, isTrue);
      expect(bluez.adapter.discoveryFilter?['Transport'],
          const DBusString('le'));
      expect(
          bluez.adapter.discoveryFilter?['UUIDs'],
          DBusArray.string(const [clarityMeshServiceUuid]));
      expect(bluez.adapter.discovering, isTrue);
      expect(bluez.adapter.registeredApp, isNotNull);
      expect(bluez.adapter.registeredAdvertisement, isNotNull);

      // Read the application tree back exactly as bluetoothd would.
      final app = DBusRemoteObjectManager(bluezClient,
          name: bluez.adapter.appOwner!, path: bluez.adapter.registeredApp!);
      final tree = await app.getManagedObjects();
      final service = tree.entries
          .where((e) => e.value.containsKey('org.bluez.GattService1'))
          .single;
      expect(service.value['org.bluez.GattService1']!['UUID'],
          const DBusString(clarityMeshServiceUuid));
      final characteristic = tree.entries
          .where((e) => e.value.containsKey('org.bluez.GattCharacteristic1'))
          .single;
      final charProps = characteristic.value['org.bluez.GattCharacteristic1']!;
      expect(charProps['UUID'], const DBusString(clarityMeshRxCharUuid));
      expect(charProps['Service'], service.key);
      expect((charProps['Flags']! as DBusArray).asStringArray(),
          containsAll(<String>['write', 'write-without-response']));

      await radio.stop();
      expect(bluez.adapter.discovering, isFalse);
      expect(bluez.adapter.registeredApp, isNull);
      expect(bluez.adapter.registeredAdvertisement, isNull);
    });

    test('discovered peer gets connected and receives chunked frames',
        () async {
      await radio.start();

      final peer = await bluez.addPeerDevice('dev_AA_00_00_00_00_01');
      await eventually(() => radio.connectedPeers.isNotEmpty,
          reason: 'radio connects to an advertised peer');
      expect(peer.connectCalls, greaterThanOrEqualTo(1));

      final small = patterned(40, 3);
      final big = patterned(6000, 4); // spans many chunks
      await radio.broadcast([small]);
      await radio.broadcast([big]);

      await eventually(() => peer.receivedFrames.length == 2,
          reason: 'both frames reassemble on the peer');
      expect(peer.receivedFrames[0], small);
      expect(peer.receivedFrames[1], big);
      for (final chunk in peer.receivedChunks) {
        expect(chunk.length, lessThanOrEqualTo(meshChunkSize));
      }

      await radio.stop();
    });

    test('inbound writes from two peers reassemble independently', () async {
      await radio.start();
      // Track what the app-facing stream delivers.
      final delivered = <Uint8List>[];
      final sub = radio.incomingFrames.listen(delivered.add);

      await bluez.addPeerDevice('dev_AA_00_00_00_00_02');
      await eventually(() => bluez.adapter.appOwner != null);

      final frameX = patterned(700, 5);
      final frameY = patterned(90, 6);
      final xChunks = chunkFrames([frameX], chunkSize: 50);
      final yChunks = chunkFrames([frameY], chunkSize: 50);

      // Interleave two devices' streams chunk by chunk, as two nearby peers
      // writing concurrently would.
      final writerX = bluez.writerFor(radio, '/org/bluez/hci0/dev_X');
      final writerY = bluez.writerFor(radio, '/org/bluez/hci0/dev_Y');
      final maxLen = xChunks.length > yChunks.length ? xChunks.length : yChunks.length;
      for (var i = 0; i < maxLen; i++) {
        if (i < xChunks.length) await writerX(xChunks[i]);
        if (i < yChunks.length) await writerY(yChunks[i]);
      }

      await eventually(() => delivered.length == 2,
          reason: 'both interleaved frames delivered');
      expect(delivered, containsAll([frameX, frameY]));

      await sub.cancel();
      await radio.stop();
    });

    test('disconnect resets a torn inbound stream', () async {
      await radio.start();
      final delivered = <Uint8List>[];
      final sub = radio.incomingFrames.listen(delivered.add);

      final peer = await bluez.addPeerDevice('dev_AA_00_00_00_00_03');
      await eventually(() => radio.connectedPeers.isNotEmpty);

      // Send only half a frame, then drop the connection.
      final torn = chunkFrames([patterned(400, 8)], chunkSize: 100);
      final write = bluez.writerFor(radio, peer.path.value);
      await write(torn.first);
      await peer.disconnect();
      await eventually(() => radio.connectedPeers.isEmpty,
          reason: 'peer drops on Connected=false');

      // A fresh, complete frame after reconnecting must come through clean —
      // the torn bytes must not poison the stream.
      final fresh = patterned(120, 9);
      for (final chunk in chunkFrames([fresh], chunkSize: 100)) {
        await write(chunk);
      }
      await eventually(() => delivered.isNotEmpty,
          reason: 'fresh frame after reset');
      expect(delivered, [fresh]);

      await sub.cancel();
      await radio.stop();
    });

    test('radio restarts cleanly (transport switching)', () async {
      await radio.start();
      await radio.stop();
      await radio.start();
      expect(bluez.adapter.registeredApp, isNotNull);
      expect(bluez.adapter.discovering, isTrue);

      final peer = await bluez.addPeerDevice('dev_AA_00_00_00_00_04');
      await eventually(() => radio.connectedPeers.isNotEmpty);
      final frame = patterned(64, 10);
      await radio.broadcast([frame]);
      await eventually(() => peer.receivedFrames.length == 1);
      expect(peer.receivedFrames.single, frame);

      await radio.stop();
    });
  });
}

/// Poll until [condition] holds, failing after a deadline.
Future<void> eventually(bool Function() condition,
    {String? reason, Duration timeout = const Duration(seconds: 5)}) async {
  final deadline = DateTime.now().add(timeout);
  while (!condition()) {
    if (DateTime.now().isAfter(deadline)) {
      fail('condition not met within $timeout${reason == null ? '' : ': $reason'}');
    }
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
}

// --- mock bluetoothd ---------------------------------------------------------

/// A fake `org.bluez` on a private bus: object manager at `/`, one adapter,
/// and peer devices addable at runtime.
class MockBluez {
  MockBluez(this.client);

  final DBusClient client;
  late final DBusObject root = DBusObject(DBusObjectPath('/'), isObjectManager: true);
  late final MockAdapter adapter = MockAdapter();
  final List<MockDevice> devices = [];

  Future<void> claim() async {
    await client.requestName('org.bluez');
    await client.registerObject(root);
    await client.registerObject(adapter);
  }

  /// A new in-range peer advertising the mesh service, its GATT tree already
  /// resolved (as after a completed service discovery).
  Future<MockDevice> addPeerDevice(String id) async {
    final device = MockDevice(DBusObjectPath('/org/bluez/hci0/$id'));
    devices.add(device);
    // Characteristic first so the tree is complete when the device announces.
    await client.registerObject(device.characteristic);
    await client.registerObject(device);
    return device;
  }

  /// Writes into the radio's exported RX characteristic the way bluetoothd
  /// relays a remote device's GATT write, attributed to [devicePath].
  Future<void> Function(Uint8List chunk) writerFor(
      BlueZMeshRadio radio, String devicePath) {
    return (chunk) async {
      await client.callMethod(
          destination: adapter.appOwner!,
          path: DBusObjectPath('/org/clarity/mesh/service0/char0'),
          interface: 'org.bluez.GattCharacteristic1',
          name: 'WriteValue',
          values: [
            DBusArray.byte(chunk),
            DBusDict.stringVariant({'device': DBusObjectPath(devicePath)}),
          ],
          replySignature: DBusSignature(''));
    };
  }
}

class MockAdapter extends DBusObject {
  MockAdapter() : super(DBusObjectPath('/org/bluez/hci0'));

  bool powered = false;
  bool discovering = false;
  Map<String, DBusValue>? discoveryFilter;
  DBusObjectPath? registeredApp;
  DBusObjectPath? registeredAdvertisement;

  /// Unique bus name of the client that registered the GATT application —
  /// how the mock reaches back into the radio, as bluetoothd does.
  String? appOwner;

  @override
  Map<String, Map<String, DBusValue>> get interfacesAndProperties => {
        'org.bluez.Adapter1': {
          'Powered': DBusBoolean(powered),
          'Discovering': DBusBoolean(discovering),
        },
      };

  @override
  Future<DBusMethodResponse> setProperty(
      String interface, String name, DBusValue value) async {
    if (interface == 'org.bluez.Adapter1' && name == 'Powered') {
      powered = value.asBoolean();
      return DBusMethodSuccessResponse();
    }
    return DBusMethodErrorResponse.unknownProperty();
  }

  @override
  Future<DBusMethodResponse> handleMethodCall(DBusMethodCall methodCall) async {
    switch ((methodCall.interface, methodCall.name)) {
      case ('org.bluez.Adapter1', 'SetDiscoveryFilter'):
        discoveryFilter = methodCall.values[0].asStringVariantDict();
        return DBusMethodSuccessResponse();
      case ('org.bluez.Adapter1', 'StartDiscovery'):
        discovering = true;
        return DBusMethodSuccessResponse();
      case ('org.bluez.Adapter1', 'StopDiscovery'):
        discovering = false;
        return DBusMethodSuccessResponse();
      case ('org.bluez.GattManager1', 'RegisterApplication'):
        registeredApp = methodCall.values[0].asObjectPath();
        appOwner = methodCall.sender;
        return DBusMethodSuccessResponse();
      case ('org.bluez.GattManager1', 'UnregisterApplication'):
        registeredApp = null;
        return DBusMethodSuccessResponse();
      case ('org.bluez.LEAdvertisingManager1', 'RegisterAdvertisement'):
        registeredAdvertisement = methodCall.values[0].asObjectPath();
        return DBusMethodSuccessResponse();
      case ('org.bluez.LEAdvertisingManager1', 'UnregisterAdvertisement'):
        registeredAdvertisement = null;
        return DBusMethodSuccessResponse();
    }
    return DBusMethodErrorResponse.unknownMethod();
  }
}

class MockDevice extends DBusObject {
  MockDevice(super.path)
      : characteristic = MockCharacteristic(
            DBusObjectPath('${path.value}/service0001/char0001'), path);

  final MockCharacteristic characteristic;
  int connectCalls = 0;
  bool connected = false;

  List<Uint8List> get receivedChunks => characteristic.chunks;
  List<Uint8List> get receivedFrames => characteristic.frames;

  Map<String, DBusValue> get _deviceProps => {
        'UUIDs': DBusArray.string(const [clarityMeshServiceUuid]),
        'Connected': DBusBoolean(connected),
        'ServicesResolved': DBusBoolean(connected),
      };

  @override
  Map<String, Map<String, DBusValue>> get interfacesAndProperties =>
      {'org.bluez.Device1': _deviceProps};

  @override
  Future<DBusMethodResponse> getProperty(String interface, String name) async {
    final value = interfacesAndProperties[interface]?[name];
    if (value == null) return DBusMethodErrorResponse.unknownProperty();
    return DBusGetPropertyResponse(value);
  }

  @override
  Future<DBusMethodResponse> getAllProperties(String interface) async {
    return DBusGetAllPropertiesResponse(interfacesAndProperties[interface] ?? {});
  }

  @override
  Future<DBusMethodResponse> handleMethodCall(DBusMethodCall methodCall) async {
    if (methodCall.interface == 'org.bluez.Device1' &&
        methodCall.name == 'Connect') {
      connectCalls += 1;
      connected = true;
      return DBusMethodSuccessResponse();
    }
    return DBusMethodErrorResponse.unknownMethod();
  }

  Future<void> disconnect() async {
    connected = false;
    await emitPropertiesChanged('org.bluez.Device1',
        changedProperties: {'Connected': const DBusBoolean(false)});
  }
}

class MockCharacteristic extends DBusObject {
  MockCharacteristic(super.path, this.servicePath);

  final DBusObjectPath servicePath;
  final List<Uint8List> chunks = [];
  final List<Uint8List> frames = [];
  final FrameAssembler _assembler = FrameAssembler();

  @override
  Map<String, Map<String, DBusValue>> get interfacesAndProperties => {
        'org.bluez.GattCharacteristic1': {
          'UUID': const DBusString(clarityMeshRxCharUuid),
          'Service': servicePath,
          'Flags': DBusArray.string(const ['write', 'write-without-response']),
        },
      };

  @override
  Future<DBusMethodResponse> getProperty(String interface, String name) async {
    final value = interfacesAndProperties[interface]?[name];
    if (value == null) return DBusMethodErrorResponse.unknownProperty();
    return DBusGetPropertyResponse(value);
  }

  @override
  Future<DBusMethodResponse> handleMethodCall(DBusMethodCall methodCall) async {
    if (methodCall.interface == 'org.bluez.GattCharacteristic1' &&
        methodCall.name == 'WriteValue') {
      final chunk = Uint8List.fromList(methodCall.values[0].asByteArray().toList());
      chunks.add(chunk);
      frames.addAll(_assembler.add(chunk));
      return DBusMethodSuccessResponse();
    }
    return DBusMethodErrorResponse.unknownMethod();
  }
}

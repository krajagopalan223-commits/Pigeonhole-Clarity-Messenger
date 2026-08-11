// User-selectable transport configuration.

/// Which transport the app uses to reach contacts.
enum TransportMode {
  /// Relay over plain HTTP(S). Simplest; use only with an outer VPN/Tor or for dev.
  relayDirect,

  /// Relay over Tor (SOCKS5). Hides your IP from the relay and the network.
  relayTor,

  /// Bluetooth store-carry-forward mesh. Works offline; broadcasts your presence.
  mesh,
}

/// Serializable transport settings.
class TransportConfig {
  const TransportConfig({
    this.mode = TransportMode.relayDirect,
    this.relayUrl = 'http://127.0.0.1:8080',
    this.torSocks = '127.0.0.1:9050',
  });

  final TransportMode mode;

  /// Relay base URL (may be a `.onion` when [mode] is [TransportMode.relayTor]).
  final String relayUrl;

  /// Tor SOCKS5 proxy address (e.g. system tor `127.0.0.1:9050`, Orbot `:9150`).
  final String torSocks;

  bool get usesRelay =>
      mode == TransportMode.relayDirect || mode == TransportMode.relayTor;

  TransportConfig copyWith({TransportMode? mode, String? relayUrl, String? torSocks}) {
    return TransportConfig(
      mode: mode ?? this.mode,
      relayUrl: relayUrl ?? this.relayUrl,
      torSocks: torSocks ?? this.torSocks,
    );
  }

  Map<String, dynamic> toJson() => {
        'mode': mode.name,
        'relayUrl': relayUrl,
        'torSocks': torSocks,
      };

  static TransportConfig fromJson(Map<String, dynamic> json) {
    return TransportConfig(
      mode: TransportMode.values.firstWhere(
        (m) => m.name == json['mode'],
        orElse: () => TransportMode.relayDirect,
      ),
      relayUrl: json['relayUrl'] as String? ?? 'http://127.0.0.1:8080',
      torSocks: json['torSocks'] as String? ?? '127.0.0.1:9050',
    );
  }
}

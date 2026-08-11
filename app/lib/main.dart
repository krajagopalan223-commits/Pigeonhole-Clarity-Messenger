// Clarity Messenger — app entry point.
//
// Configure the relay at build/run time:
//   flutter run --dart-define=CLARITY_RELAY=https://relay.example.org

import 'package:flutter/material.dart';

import 'src/state/app_state.dart';
import 'src/ui/home_screen.dart';

const _relayUrl = String.fromEnvironment(
  'CLARITY_RELAY',
  defaultValue: 'http://127.0.0.1:8080',
);

void main() {
  runApp(const ClarityApp());
}

class ClarityApp extends StatefulWidget {
  const ClarityApp({super.key});

  @override
  State<ClarityApp> createState() => _ClarityAppState();
}

class _ClarityAppState extends State<ClarityApp> {
  late final AppState _state = AppState(relayUrl: _relayUrl);
  late final Future<void> _init = _state.initialize();

  @override
  void dispose() {
    _state.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Clarity Messenger',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF2E6EEA),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      home: FutureBuilder<void>(
        future: _init,
        builder: (context, snapshot) {
          if (snapshot.connectionState != ConnectionState.done) {
            return const Scaffold(
              body: Center(child: CircularProgressIndicator()),
            );
          }
          if (snapshot.hasError) {
            return Scaffold(
              body: Center(
                child: Padding(
                  padding: const EdgeInsets.all(24),
                  child: Text('Startup failed:\n${snapshot.error}',
                      textAlign: TextAlign.center),
                ),
              ),
            );
          }
          return HomeScreen(state: _state);
        },
      ),
    );
  }
}

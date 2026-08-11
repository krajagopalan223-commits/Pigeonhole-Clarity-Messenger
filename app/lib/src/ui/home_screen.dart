// Conversation list + "your identity" + add-contact flow.

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models/models.dart';
import '../state/app_state.dart';
import 'chat_screen.dart';

class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key, required this.state});

  final AppState state;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: state,
      builder: (context, _) {
        final contacts = state.contacts;
        return Scaffold(
          appBar: AppBar(
            title: const Text('Clarity'),
            actions: [
              IconButton(
                icon: const Icon(Icons.fingerprint),
                tooltip: 'Your identity',
                onPressed: () => _showMyIdentity(context),
              ),
            ],
          ),
          body: contacts.isEmpty
              ? const _EmptyState()
              : ListView.separated(
                  itemCount: contacts.length,
                  separatorBuilder: (_, __) => const Divider(height: 1),
                  itemBuilder: (context, i) => _ContactTile(
                    state: state,
                    contact: contacts[i],
                  ),
                ),
          floatingActionButton: FloatingActionButton.extended(
            onPressed: () => _addContact(context),
            icon: const Icon(Icons.person_add),
            label: const Text('Add contact'),
          ),
        );
      },
    );
  }

  void _showMyIdentity(BuildContext context) {
    final id = state.myIdentity;
    final text = id == null ? '(not ready)' : base64.encode(id);
    showDialog<void>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Your identity key'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Share this with contacts so they can message you:'),
            const SizedBox(height: 12),
            SelectableText(text, style: const TextStyle(fontFamily: 'monospace')),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: text));
              Navigator.pop(context);
            },
            child: const Text('Copy'),
          ),
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Close')),
        ],
      ),
    );
  }

  Future<void> _addContact(BuildContext context) async {
    final nameCtrl = TextEditingController();
    final idCtrl = TextEditingController();
    final result = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Add contact'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: nameCtrl,
              decoration: const InputDecoration(labelText: 'Display name'),
            ),
            TextField(
              controller: idCtrl,
              decoration: const InputDecoration(labelText: 'Identity key (base64)'),
              maxLines: 2,
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(context, true), child: const Text('Add')),
        ],
      ),
    );
    if (result != true) return;

    try {
      final identity = Uint8List.fromList(base64.decode(idCtrl.text.trim()));
      final name = nameCtrl.text.trim().isEmpty ? 'Unnamed' : nameCtrl.text.trim();
      await state.addContact(identity, name);
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Could not add contact: $e')),
        );
      }
    }
  }
}

class _ContactTile extends StatelessWidget {
  const _ContactTile({required this.state, required this.contact});

  final AppState state;
  final Contact contact;

  @override
  Widget build(BuildContext context) {
    final messages = state.conversation(contact.id);
    final last = messages.isNotEmpty ? messages.last.text : 'No messages yet';
    return ListTile(
      leading: CircleAvatar(child: Text(contact.displayName.characters.first.toUpperCase())),
      title: Row(
        children: [
          Text(contact.displayName),
          if (contact.verified)
            const Padding(
              padding: EdgeInsets.only(left: 6),
              child: Icon(Icons.verified_user, size: 16, color: Colors.greenAccent),
            ),
        ],
      ),
      subtitle: Text(last, maxLines: 1, overflow: TextOverflow.ellipsis),
      onTap: () => Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => ChatScreen(state: state, contactId: contact.id)),
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Padding(
        padding: EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.lock_outline, size: 48),
            SizedBox(height: 16),
            Text(
              'No conversations yet.\nTap "Add contact" and paste an identity key to start.',
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}

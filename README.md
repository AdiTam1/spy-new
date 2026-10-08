# Spy (המרגל)

A Hebrew party game in the style of Spyfall, playable in the browser with no server of our own.

- The host opens a room and shares a 5-character code or link.
- Up to 30 players join. While people join, the host picks the number of spies and the round length (recommendations update automatically).
- Each player sees only their own role: roles are end-to-end encrypted (ECDH P-256 + AES-GCM) from the host's browser to each player.

## How it works

The host's browser is the game server. All devices talk through the public MQTT broker `broker.hivemq.com` over secure WebSocket. Public room state (players, settings, timer) is a retained message; roles go to per-player topics, encrypted.

If the host closes the tab, the game pauses until the host returns. The room state is saved in the host's browser, so reopening the page resumes it.

## Local testing

Serve the folder over `http://localhost` and point the page at any MQTT-over-WebSocket broker with `?broker=ws://localhost:8888/mqtt`.

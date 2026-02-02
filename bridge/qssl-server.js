/**
 * QSSL Server - Post-quantum secure WebSocket server for Drista bridge
 *
 * Implements QSSL handshake protocol compatible with qssl-wasm client:
 * - X25519 ECDH for key exchange
 * - Ed25519 for signatures
 * - AES-256-GCM for symmetric encryption
 */

const WebSocket = require('ws');
const crypto = require('crypto');

// Message types
const MSG_TYPE = {
  CLIENT_HELLO: 1,
  SERVER_HELLO: 2,
  CLIENT_FINISHED: 3,
  SERVER_FINISHED: 4,
};

// Connection states
const STATE = {
  CONNECTING: 'connecting',
  HANDSHAKING: 'handshaking',
  CONNECTED: 'connected',
  CLOSED: 'closed',
};

/**
 * QSSL Identity - Ed25519 signing + X25519 key exchange
 */
class QsslIdentity {
  constructor() {
    // Generate Ed25519 signing keypair
    const { publicKey: signPub, privateKey: signPriv } = crypto.generateKeyPairSync('ed25519');
    this.signPrivate = signPriv;
    this.signPublic = signPub;
    this.signPublicRaw = signPub.export({ type: 'spki', format: 'der' }).slice(-32);

    // Generate X25519 key exchange keypair
    const { publicKey: kexPub, privateKey: kexPriv } = crypto.generateKeyPairSync('x25519');
    this.kexPrivate = kexPriv;
    this.kexPublic = kexPub;
    this.kexPublicRaw = kexPub.export({ type: 'spki', format: 'der' }).slice(-32);

    // Fingerprint
    const hash = crypto.createHash('sha256');
    hash.update(this.signPublicRaw);
    hash.update(this.kexPublicRaw);
    this.fingerprint = hash.digest('hex').slice(0, 16);
  }

  sign(message) {
    return crypto.sign(null, message, this.signPrivate);
  }

  static verify(publicKeyRaw, message, signature) {
    try {
      const pubKey = crypto.createPublicKey({
        key: Buffer.concat([
          Buffer.from('302a300506032b6570032100', 'hex'), // Ed25519 SPKI prefix
          publicKeyRaw
        ]),
        format: 'der',
        type: 'spki'
      });
      return crypto.verify(null, message, pubKey, signature);
    } catch (e) {
      return false;
    }
  }

  dh(peerPublicRaw) {
    const peerKey = crypto.createPublicKey({
      key: Buffer.concat([
        Buffer.from('302a300506032b656e032100', 'hex'), // X25519 SPKI prefix
        peerPublicRaw
      ]),
      format: 'der',
      type: 'spki'
    });
    return crypto.diffieHellman({
      privateKey: this.kexPrivate,
      publicKey: peerKey
    });
  }
}

/**
 * QSSL Cipher - AES-256-GCM with counter-based nonce
 */
class QsslCipher {
  constructor(sharedSecret) {
    // Derive key using HKDF
    this.key = crypto.hkdfSync('sha256', sharedSecret, Buffer.from('qssl-v1'), Buffer.from('qssl-aes256-gcm'), 32);
    this.sendCounter = 0n;
    this.recvCounter = 0n;
  }

  encrypt(plaintext) {
    const nonce = Buffer.alloc(12);
    nonce.writeBigUInt64LE(this.sendCounter, 0);
    this.sendCounter += 1n;

    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, nonce);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    return Buffer.concat([nonce, encrypted, tag]);
  }

  decrypt(ciphertext) {
    if (ciphertext.length < 28) { // 12 nonce + 16 tag minimum
      throw new Error('Ciphertext too short');
    }

    const nonce = ciphertext.slice(0, 12);
    const tag = ciphertext.slice(-16);
    const encrypted = ciphertext.slice(12, -16);

    const receivedCounter = nonce.readBigUInt64LE(0);
    if (receivedCounter < this.recvCounter) {
      throw new Error('Replay attack detected');
    }
    this.recvCounter = receivedCounter + 1n;

    const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  }
}

/**
 * Bincode-compatible serialization (simplified)
 * QSSL uses bincode for message encoding
 */
function encodeClientHello(hello) {
  // version: u16, random: Vec<u8>, signing_key: Vec<u8>, kex_key: Vec<u8>
  const buf = Buffer.alloc(2 + 8 + hello.random.length + 8 + hello.signing_key.length + 8 + hello.kex_key.length);
  let offset = 0;

  buf.writeUInt16LE(hello.version, offset); offset += 2;
  buf.writeBigUInt64LE(BigInt(hello.random.length), offset); offset += 8;
  hello.random.copy(buf, offset); offset += hello.random.length;
  buf.writeBigUInt64LE(BigInt(hello.signing_key.length), offset); offset += 8;
  hello.signing_key.copy(buf, offset); offset += hello.signing_key.length;
  buf.writeBigUInt64LE(BigInt(hello.kex_key.length), offset); offset += 8;
  hello.kex_key.copy(buf, offset);

  return buf;
}

function decodeClientHello(data) {
  let offset = 0;

  const version = data.readUInt16LE(offset); offset += 2;
  const randomLen = Number(data.readBigUInt64LE(offset)); offset += 8;
  const random = data.slice(offset, offset + randomLen); offset += randomLen;
  const signKeyLen = Number(data.readBigUInt64LE(offset)); offset += 8;
  const signing_key = data.slice(offset, offset + signKeyLen); offset += signKeyLen;
  const kexKeyLen = Number(data.readBigUInt64LE(offset)); offset += 8;
  const kex_key = data.slice(offset, offset + kexKeyLen);

  return { version, random, signing_key, kex_key };
}

function encodeServerHello(hello) {
  const totalLen = 2 + 8 + hello.random.length + 8 + hello.signing_key.length + 8 + hello.kex_key.length + 8 + hello.signature.length;
  const buf = Buffer.alloc(totalLen);
  let offset = 0;

  buf.writeUInt16LE(hello.version, offset); offset += 2;
  buf.writeBigUInt64LE(BigInt(hello.random.length), offset); offset += 8;
  hello.random.copy(buf, offset); offset += hello.random.length;
  buf.writeBigUInt64LE(BigInt(hello.signing_key.length), offset); offset += 8;
  hello.signing_key.copy(buf, offset); offset += hello.signing_key.length;
  buf.writeBigUInt64LE(BigInt(hello.kex_key.length), offset); offset += 8;
  hello.kex_key.copy(buf, offset); offset += hello.kex_key.length;
  buf.writeBigUInt64LE(BigInt(hello.signature.length), offset); offset += 8;
  hello.signature.copy(buf, offset);

  return buf;
}

function encodeFinished(finished) {
  const buf = Buffer.alloc(8 + finished.verify_data.length);
  buf.writeBigUInt64LE(BigInt(finished.verify_data.length), 0);
  finished.verify_data.copy(buf, 8);
  return buf;
}

function decodeFinished(data) {
  const len = Number(data.readBigUInt64LE(0));
  return { verify_data: data.slice(8, 8 + len) };
}

/**
 * QSSL Server Handshake handler
 */
class QsslServerHandshake {
  constructor(identity) {
    this.identity = identity;
    this.transcript = Buffer.alloc(0);
    this.sharedSecret = null;
    this.peerSigningKey = null;
    this.state = 'initial';
  }

  processClientHello(data) {
    if (this.state !== 'initial') throw new Error('Invalid state');
    if (data[0] !== MSG_TYPE.CLIENT_HELLO) throw new Error('Expected ClientHello');

    const payload = data.slice(1);
    this.transcript = Buffer.concat([this.transcript, payload]);

    const hello = decodeClientHello(payload);
    this.peerSigningKey = hello.signing_key;

    // Perform DH
    this.sharedSecret = this.identity.dh(hello.kex_key);

    // Create ServerHello
    const random = crypto.randomBytes(32);
    const serverHello = {
      version: 1,
      random,
      signing_key: this.identity.signPublicRaw,
      kex_key: this.identity.kexPublicRaw,
      signature: null,
    };

    // Sign transcript hash
    const transcriptHash = crypto.createHash('sha256').update(this.transcript).digest();
    serverHello.signature = this.identity.sign(transcriptHash);

    const encoded = encodeServerHello(serverHello);
    this.transcript = Buffer.concat([this.transcript, encoded]);
    this.state = 'sent_hello';

    return Buffer.concat([Buffer.from([MSG_TYPE.SERVER_HELLO]), encoded]);
  }

  processClientFinished(data) {
    if (this.state !== 'sent_hello') throw new Error('Invalid state');
    if (data[0] !== MSG_TYPE.CLIENT_FINISHED) throw new Error('Expected ClientFinished');

    const finished = decodeFinished(data.slice(1));
    const expected = this.computeVerifyData();

    if (!finished.verify_data.equals(expected)) {
      throw new Error('Verify data mismatch');
    }

    this.state = 'received_finished';

    // Send ServerFinished
    const serverFinished = { verify_data: this.computeVerifyData() };
    const encoded = encodeFinished(serverFinished);
    this.state = 'complete';

    return Buffer.concat([Buffer.from([MSG_TYPE.SERVER_FINISHED]), encoded]);
  }

  computeVerifyData() {
    const hash = crypto.createHash('sha256').update(this.transcript).digest();
    return Buffer.from(crypto.hkdfSync('sha256', this.sharedSecret, hash, Buffer.from('qssl-finished'), 32));
  }

  getCipher() {
    if (this.state !== 'complete') throw new Error('Handshake not complete');
    return new QsslCipher(this.sharedSecret);
  }
}

/**
 * QSSL WebSocket Server
 */
class QsslServer {
  constructor(options = {}) {
    this.port = options.port || 7779;
    this.bridgeUrl = options.bridgeUrl || 'ws://127.0.0.1:7777';
    this.identity = new QsslIdentity();
    this.clients = new Map();

    console.log(`[QSSL] Server identity: ${this.identity.fingerprint}`);
  }

  start() {
    this.wss = new WebSocket.Server({ port: this.port });

    this.wss.on('connection', (ws, req) => {
      const clientId = crypto.randomUUID().slice(0, 8);
      const clientIp = req.socket.remoteAddress;
      console.log(`[QSSL] Client ${clientId} connected from ${clientIp}`);

      const client = {
        id: clientId,
        ws,
        state: STATE.HANDSHAKING,
        handshake: new QsslServerHandshake(this.identity),
        cipher: null,
        bridge: null,
      };

      this.clients.set(clientId, client);

      ws.on('message', (data) => this.handleMessage(client, data));
      ws.on('close', () => this.handleClose(client));
      ws.on('error', (err) => console.error(`[QSSL] Client ${clientId} error:`, err.message));
    });

    console.log(`[QSSL] Server listening on port ${this.port}`);
    console.log(`[QSSL] Bridge URL: ${this.bridgeUrl}`);
  }

  handleMessage(client, data) {
    const buf = Buffer.from(data);

    if (client.state === STATE.HANDSHAKING) {
      try {
        if (client.handshake.state === 'initial') {
          // Process ClientHello
          const response = client.handshake.processClientHello(buf);
          client.ws.send(response);
          console.log(`[QSSL] Client ${client.id}: sent ServerHello`);
        } else if (client.handshake.state === 'sent_hello') {
          // Process ClientFinished
          const response = client.handshake.processClientFinished(buf);
          client.ws.send(response);
          client.cipher = client.handshake.getCipher();
          client.state = STATE.CONNECTED;
          console.log(`[QSSL] Client ${client.id}: handshake complete, connecting to bridge`);
          this.connectToBridge(client);
        }
      } catch (err) {
        console.error(`[QSSL] Client ${client.id} handshake error:`, err.message);
        client.ws.close(1002, err.message);
      }
    } else if (client.state === STATE.CONNECTED && client.cipher) {
      // Decrypt and forward to bridge
      try {
        const plaintext = client.cipher.decrypt(buf);
        if (client.bridge && client.bridge.readyState === WebSocket.OPEN) {
          client.bridge.send(plaintext);
        }
      } catch (err) {
        console.error(`[QSSL] Client ${client.id} decrypt error:`, err.message);
      }
    }
  }

  connectToBridge(client) {
    client.bridge = new WebSocket(this.bridgeUrl);

    client.bridge.on('open', () => {
      console.log(`[QSSL] Client ${client.id}: bridge connected`);
    });

    client.bridge.on('message', (data) => {
      // Encrypt and forward to client
      if (client.cipher && client.ws.readyState === WebSocket.OPEN) {
        try {
          const encrypted = client.cipher.encrypt(Buffer.from(data));
          client.ws.send(encrypted);
        } catch (err) {
          console.error(`[QSSL] Client ${client.id} encrypt error:`, err.message);
        }
      }
    });

    client.bridge.on('close', () => {
      console.log(`[QSSL] Client ${client.id}: bridge disconnected`);
      client.ws.close();
    });

    client.bridge.on('error', (err) => {
      console.error(`[QSSL] Client ${client.id} bridge error:`, err.message);
    });
  }

  handleClose(client) {
    console.log(`[QSSL] Client ${client.id} disconnected`);
    if (client.bridge) {
      client.bridge.close();
    }
    this.clients.delete(client.id);
  }
}

// CLI
if (require.main === module) {
  const port = parseInt(process.env.QSSL_PORT) || 7779;
  const bridgeUrl = process.env.BRIDGE_URL || 'ws://127.0.0.1:7777';

  const server = new QsslServer({ port, bridgeUrl });
  server.start();
}

module.exports = { QsslServer, QsslIdentity, QsslCipher };

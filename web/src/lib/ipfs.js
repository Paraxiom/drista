/**
 * IPFS Integration for Drista
 *
 * Hybrid storage: Content on IPFS, hashes/CIDs on-chain
 * This reduces blockchain storage costs significantly.
 */

// Public IPFS gateways for reading
const IPFS_GATEWAYS = [
  'https://ipfs.io/ipfs/',
  'https://cloudflare-ipfs.com/ipfs/',
  'https://gateway.pinata.cloud/ipfs/',
  'https://dweb.link/ipfs/',
];

// IPFS HTTP API endpoints for writing (can be local or pinning service)
const IPFS_API_ENDPOINTS = [
  'https://ipfs.infura.io:5001/api/v0',  // Infura (requires auth)
  'http://localhost:5001/api/v0',         // Local IPFS node
];

// Pinata API for reliable pinning (if configured)
const PINATA_API = 'https://api.pinata.cloud';
let pinataJwt = null;

/**
 * Configure Pinata for reliable IPFS pinning
 */
export function configurePinata(jwt) {
  pinataJwt = jwt;
  console.log('[IPFS] Pinata configured');
}

/**
 * Upload content to IPFS
 * Returns the CID (Content Identifier)
 */
export async function uploadToIPFS(content) {
  const data = typeof content === 'string' ? content : JSON.stringify(content);
  const blob = new Blob([data], { type: 'application/json' });

  // Try Pinata first if configured
  if (pinataJwt) {
    try {
      const cid = await uploadToPinata(blob);
      console.log('[IPFS] Uploaded to Pinata:', cid);
      return cid;
    } catch (error) {
      console.warn('[IPFS] Pinata upload failed, trying alternatives:', error);
    }
  }

  // Try web3.storage or other public services
  try {
    const cid = await uploadToWeb3Storage(blob);
    console.log('[IPFS] Uploaded to web3.storage:', cid);
    return cid;
  } catch (error) {
    console.warn('[IPFS] web3.storage failed:', error);
  }

  // Fallback: Try local IPFS node
  try {
    const cid = await uploadToLocalIPFS(blob);
    console.log('[IPFS] Uploaded to local node:', cid);
    return cid;
  } catch (error) {
    console.warn('[IPFS] Local IPFS failed:', error);
  }

  throw new Error('All IPFS upload methods failed');
}

/**
 * Upload to Pinata pinning service
 */
async function uploadToPinata(blob) {
  const formData = new FormData();
  formData.append('file', blob, 'message.json');

  const response = await fetch(`${PINATA_API}/pinning/pinFileToIPFS`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${pinataJwt}`,
    },
    body: formData,
  });

  if (!response.ok) {
    throw new Error(`Pinata error: ${response.status}`);
  }

  const result = await response.json();
  return result.IpfsHash;
}

/**
 * Upload using simple fetch to public IPFS add endpoint
 * This uses a relay/proxy approach
 */
async function uploadToWeb3Storage(blob) {
  // For now, we'll use a simple approach with the validator's IPFS node
  // In production, you'd use web3.storage API with an API token

  const formData = new FormData();
  formData.append('file', blob);

  // Try the validator's IPFS proxy
  const response = await fetch('https://drista.paraxiom.org/ipfs/add', {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    throw new Error(`Upload error: ${response.status}`);
  }

  const result = await response.json();
  return result.Hash || result.cid;
}

/**
 * Upload to local IPFS node
 */
async function uploadToLocalIPFS(blob) {
  const formData = new FormData();
  formData.append('file', blob);

  const response = await fetch('http://localhost:5001/api/v0/add', {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    throw new Error(`Local IPFS error: ${response.status}`);
  }

  const result = await response.json();
  return result.Hash;
}

/**
 * Fetch content from IPFS by CID
 * Tries multiple gateways for reliability
 */
export async function fetchFromIPFS(cid, timeout = 10000) {
  const errors = [];

  for (const gateway of IPFS_GATEWAYS) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(`${gateway}${cid}`, {
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const text = await response.text();
        try {
          return JSON.parse(text);
        } catch {
          return text;
        }
      }
    } catch (error) {
      errors.push(`${gateway}: ${error.message}`);
    }
  }

  console.error('[IPFS] All gateways failed:', errors);
  throw new Error(`Failed to fetch from IPFS: ${cid}`);
}

/**
 * Create a message envelope for hybrid storage
 */
export function createMessageEnvelope(content, sender, channel) {
  return {
    version: 2,
    type: 'drista-message',
    content,
    sender,
    channel,
    timestamp: Date.now(),
  };
}

/**
 * Create on-chain reference (small footprint)
 */
export function createOnChainReference(cid, contentHash, sender) {
  return {
    v: 2,                    // Version
    cid,                     // IPFS CID
    h: contentHash,          // SHA-256 hash of content (for verification)
    s: sender,               // Sender identifier
    t: Date.now(),           // Timestamp
  };
}

/**
 * Compute SHA-256 hash of content
 */
export async function hashContent(content) {
  const data = typeof content === 'string' ? content : JSON.stringify(content);
  const encoder = new TextEncoder();
  const buffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Verify content matches hash
 */
export async function verifyContent(content, expectedHash) {
  const actualHash = await hashContent(content);
  return actualHash === expectedHash;
}

/**
 * Check if a string looks like an IPFS CID
 */
export function isIPFSCid(str) {
  if (!str || typeof str !== 'string') return false;
  // CIDv0 starts with Qm, CIDv1 starts with b
  return str.startsWith('Qm') || str.startsWith('bafy') || str.startsWith('bafk');
}

/**
 * Get IPFS status
 */
export function getIPFSStatus() {
  return {
    gateways: IPFS_GATEWAYS.length,
    pinataConfigured: !!pinataJwt,
  };
}

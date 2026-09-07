export const CONFIG = {
  // Temel Sunucu ve Ağ Portları
  serverName: process.env.SERVER_NAME || 'localhost',
  clientPort: parseInt(process.env.CLIENT_PORT || '2222', 10),
  sshPort: parseInt(process.env.SSH_PORT || '2224', 10),
  federationPort: parseInt(process.env.FED_PORT || '8001', 10),
  defaultFedPort: 8001,

  // SSH-2 Sunucu Ayarları
  sshServerVersion: process.env.SSH_SERVER_VERSION || 'SSH-2.0-Metrice_2.1.6',

  // Metrice v2.0 P2P-Mesh, AutoNAT ve Buluşma Noktası (Rendezvous) Ayarları
  meshRole: process.env.MESH_ROLE || 'EDGE', // 'RELAY' veya 'EDGE'
  maxRendezvousTunnels: parseInt(process.env.MAX_RENDEZVOUS_TUNNELS || '64', 10),
  rendezvousKeepaliveInterval: parseInt(process.env.RENDEZVOUS_KEEPALIVE_MS || '30000', 10),
  presenceTtl: parseInt(process.env.PRESENCE_TTL_MS || '60000', 10),
  circuitTtl: parseInt(process.env.CIRCUIT_TTL_MS || '600000', 10),
  uniformCellSize: parseInt(process.env.UNIFORM_CELL_SIZE || '2048', 10),
  secureBufferLimit: parseInt(process.env.SECURE_BUFFER_LIMIT || '65536', 10),

  // Güvenlik, Proxy ve Çalışma Ortamı
  trustProxy: process.env.TRUST_PROXY === 'true' || process.env.DOCKER === 'true' || process.env.CONTAINER === 'true',
  strictPq: process.env.STRICT_PQ === 'true',
  environment: process.env.NODE_ENV || 'production',

  // Veritabanı, Eş Önbelleği ve Günlük Seviyesi
  dbFile: process.env.DB_FILE || `./data_${process.env.FED_PORT || '8001'}.db`,
  peerCacheFile: process.env.PEER_FILE || `./peers_${process.env.FED_PORT || '8001'}.json`,
  logLevel: process.env.LOG_LEVEL || 'DEBUG'
};
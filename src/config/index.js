export const CONFIG = {
  serverName: process.env.SERVER_NAME || 'localhost',
  clientPort: parseInt(process.env.CLIENT_PORT || '2222', 10),
  sshPort: parseInt(process.env.SSH_PORT || '2224', 10),
  federationPort: parseInt(process.env.FED_PORT || '8001', 10),
  defaultFedPort: 8001,
  dbFile: process.env.DB_FILE || `./data_${process.env.FED_PORT || '8001'}.db`,
  peerCacheFile: process.env.PEER_FILE || `./peers_${process.env.FED_PORT || '8001'}.json`,
  logLevel: process.env.LOG_LEVEL || 'DEBUG'
};
module.exports = {
  apps: [
    {
      name: 'metrice-node',
      script: 'src/index.js',
      cwd: './',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
      env: {
        NODE_ENV: 'production',
        TRUST_PROXY: 'true',
        MESH_ROLE: 'RELAY',
        FED_PORT: '8001',
        SSH_PORT: '2223',
        CLIENT_PORT: '2222',
        HEALTH_PORT: '8050',
        LOG_LEVEL: 'INFO',
        DB_FILE: './data/data_8001.db',
        PEER_FILE: './data/peers_8001.json'
      },
      env_edge: {
        NODE_ENV: 'production',
        TRUST_PROXY: 'false',
        MESH_ROLE: 'EDGE',
        FED_PORT: '9001',
        SSH_PORT: '2224',
        CLIENT_PORT: '2221',
        HEALTH_PORT: '8051',
        LOG_LEVEL: 'DEBUG',
        DB_FILE: './data/data_edge.db',
        PEER_FILE: './data/peers_edge.json'
      }
    }
  ]
};

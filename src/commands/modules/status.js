import { I18n } from '../../locales/i18n.js';

export default {
  name: 'status',
  aliases: ['stats', 'info'],
  description: I18n.t('CMD_STATUS_DESC'),
  usage: '/status',
  execute({ session, clientServer, federation, db }) {
    const uptimeSec = Math.floor(process.uptime());
    const hours = Math.floor(uptimeSec / 3600);
    const mins = Math.floor((uptimeSec % 3600) / 60);
    const secs = uptimeSec % 60;
    const uptimeStr = `${hours}h ${mins}m ${secs}s`;

    const mem = process.memoryUsage();
    const rssMB = (mem.rss / 1024 / 1024).toFixed(2);
    const heapMB = (mem.heapUsed / 1024 / 1024).toFixed(2);

    const onlineCount = clientServer.getOnlineUsers().length;
    const peers = federation.peerManager ? federation.peerManager.getAllPeers() : [];
    const outboxCount = db.getPendingOutbox().length;

    const rendezvousInfo = federation.isRelay()
      ? I18n.t('CMD_STATUS_RDV_TUNNELS', { current: federation.rendezvousTunnels.size, max: 64 })
      : I18n.t('CMD_STATUS_RDV_RELAYS', { relays: Array.from(federation.boundRendezvousRelays).join(', ') || I18n.t('CMD_STATUS_NONE') });

    session.addSystemLog(I18n.t('CMD_STATUS_HEADER'));
    session.addSystemLog(I18n.t('CMD_STATUS_NODE', { nodeId: federation.nodeId, address: federation.meshAddress, role: federation.role || 'EDGE' }));
    session.addSystemLog(rendezvousInfo);
    session.addSystemLog(I18n.t('CMD_STATUS_UPTIME', { uptime: uptimeStr }));
    session.addSystemLog(I18n.t('CMD_STATUS_MEMORY', { rss: rssMB, heap: heapMB }));
    session.addSystemLog(I18n.t('CMD_STATUS_CLIENTS', { count: onlineCount }));
    session.addSystemLog(I18n.t('CMD_STATUS_PEERS', { count: peers.length, peers: peers.join(', ') || '-' }));
    session.addSystemLog(I18n.t('CMD_STATUS_OUTBOX', { count: outboxCount }));
  }
};
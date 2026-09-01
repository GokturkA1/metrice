import { I18n } from '../../locales/i18n.js';

export default {
  name: 'peers',
  aliases: ['nodes', 'mesh'],
  description: I18n.t('CMD_PEERS_DESC'),
  usage: '/peers',
  execute({ session, federation }) {
    const peers = federation.peerManager ? federation.peerManager.getAllPeers() : [];
    const info = peers.length > 0 ? peers.join(', ') : I18n.t('CMD_PEERS_EMPTY');
    session.addSystemLog(I18n.t('CMD_PEERS_RESULT', { count: peers.length, peers: info }));
  }
};
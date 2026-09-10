FROM node:26-alpine

# Calisma dizini
WORKDIR /app

# Guvenlik: Dizin yapilandirmasi ve sahiplik node kullanicisina devredilir
RUN mkdir -p /app/data && chown -R node:node /app

# Paket tanimi (Zero-dependency mimarisi, type: module icin package.json gereklidir)
COPY --chown=node:node package.json ./

# Kaynak kodlar
COPY --chown=node:node src/ ./src/

# Veri kaliciligi icin veri hacmi
VOLUME ["/app/data"]

# Varsayilan ortam degiskenleri
ENV NODE_ENV=production \
    FED_PORT=8001 \
    SSH_PORT=2224 \
    CLIENT_PORT=2222 \
    DB_FILE=/app/data/data_8001.db \
    PEER_FILE=/app/data/peers_8001.json

# Ag portlari:
# 8001: P2P Mesh / Federasyon
# 2222: Telnet / Istemci Terminali
# 2223: Ozel SSH Portu (Compose eslemesi)
# 2224: Varsayilan SSH Portu
EXPOSE 8001 2222 2223 2224

# Ayrik ve guvenli non-root calistirma
USER node

# Saglik denetimi (Federasyon portuna yerlesik TCP soket kontrolu)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node --input-type=module -e "import net from 'node:net'; const s = net.connect(process.env.FED_PORT || 8001, '127.0.0.1', () => { s.end(); process.exit(0); }); s.on('error', () => process.exit(1));"

# Uygulama baslangici
CMD ["node", "src/index.js"]

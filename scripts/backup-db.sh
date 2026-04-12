#!/bin/sh
# backup-db.sh — Backup diário do SQLite para Cloudflare R2
# Executado como cron job dentro do container Railway
# 
# Variáveis necessárias:
#   DB_PATH           — caminho do banco (ex: /data/ticketradar.db)
#   R2_ACCOUNT_ID     — Cloudflare Account ID
#   R2_ACCESS_KEY_ID  — R2 Access Key ID
#   R2_SECRET_KEY     — R2 Secret Access Key
#   R2_BUCKET         — nome do bucket (ex: ticketradar-backups)
#   R2_ENDPOINT       — https://{account_id}.r2.cloudflarestorage.com

set -e

DB_PATH="${DB_PATH:-/data/ticketradar.db}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="/tmp/ticketradar_backup_${TIMESTAMP}.db"

# Criar cópia segura do SQLite (usando o modo WAL)
echo "[backup] Iniciando backup de ${DB_PATH}..."
sqlite3 "${DB_PATH}" ".backup ${BACKUP_FILE}"

BACKUP_SIZE=$(wc -c < "${BACKUP_FILE}")
echo "[backup] Backup criado: ${BACKUP_FILE} (${BACKUP_SIZE} bytes)"

# Upload para R2 via AWS CLI (compatível com S3)
if [ -n "${R2_ACCOUNT_ID}" ] && [ -n "${R2_ACCESS_KEY_ID}" ]; then
  AWS_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID}" \
  AWS_SECRET_ACCESS_KEY="${R2_SECRET_KEY}" \
  aws s3 cp "${BACKUP_FILE}" \
    "s3://${R2_BUCKET:-ticketradar-backups}/daily/ticketradar_${TIMESTAMP}.db" \
    --endpoint-url "${R2_ENDPOINT:-https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com}" \
    --region auto \
    --no-progress

  echo "[backup] ✅ Upload para R2 concluído: daily/ticketradar_${TIMESTAMP}.db"
  
  # Manter apenas os últimos 30 backups
  BACKUP_COUNT=$(AWS_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID}" \
    AWS_SECRET_ACCESS_KEY="${R2_SECRET_KEY}" \
    aws s3 ls "s3://${R2_BUCKET:-ticketradar-backups}/daily/" \
      --endpoint-url "${R2_ENDPOINT:-https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com}" \
      --region auto | wc -l)
  echo "[backup] Total de backups no R2: ${BACKUP_COUNT}"
else
  echo "[backup] ⚠️  R2 não configurado — backup salvo apenas localmente em ${BACKUP_FILE}"
  echo "[backup] Configure: R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_KEY no Railway"
fi

# Limpar arquivo temporário
rm -f "${BACKUP_FILE}"
echo "[backup] Concluído às $(date)"

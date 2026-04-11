#!/bin/sh
# Garantir que /data é gravável pelo usuário atual
# O volume Railway é montado como root em runtime
# Este script roda como root ANTES de trocar para o usuário da app

# Cria o diretório /data se não existir e ajusta permissões
mkdir -p /data
chown -R ticketradar:ticketradar /data
chmod 750 /data

# Troca para o usuário não-root e executa o app
exec su-exec ticketradar ./ticketradar

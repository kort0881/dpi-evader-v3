#!/bin/bash
# android_launcher.sh — Запуск DPI Evader v3 на Android через Termux + Shizuku
#
# Предварительные требования:
#   1. Установить Termux (F-Droid версию)
#   2. Установить Shizuku и активировать
#   3. В Termux: pkg install python clang libffi openssl
#   4. pip install scapy requests pyyaml
#
# Использование:
#   chmod +x android_launcher.sh
#   ./android_launcher.sh
#   ./android_launcher.sh --domain youtube.com
#   ./android_launcher.sh --methods 1  # Только метод 1 (без root)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EVADER_SCRIPT="$SCRIPT_DIR/dpi_evader.py"
CONFIG_FILE="$SCRIPT_DIR/config.yaml"

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║    DPI Evader v3 — Android Launcher    ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo

# ─── Проверка окружения ───

# Проверяем Termux
if [ ! -d "/data/data/com.termux" ] && [ -z "$TERMUX_VERSION" ]; then
    echo -e "${YELLOW}⚠ Не обнаружен Termux. Скрипт предназначен для Android.${NC}"
    echo -e "${YELLOW}  На Linux запускайте напрямую: sudo python3 dpi_evader.py${NC}"
fi

# Проверяем Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python3 не найден${NC}"
    echo "  Установите: pkg install python"
    exit 1
fi
echo -e "${GREEN}✓ Python3: $(python3 --version)${NC}"

# Проверяем зависимости Python
echo -n "  Проверка зависимостей... "
MISSING_DEPS=""

python3 -c "import yaml" 2>/dev/null || MISSING_DEPS="$MISSING_DEPS pyyaml"
python3 -c "import requests" 2>/dev/null || MISSING_DEPS="$MISSING_DEPS requests"

if [ -n "$MISSING_DEPS" ]; then
    echo -e "${YELLOW}Устанавливаю:${MISSING_DEPS}${NC}"
    pip install $MISSING_DEPS
else
    echo -e "${GREEN}OK${NC}"
fi

# Scapy (опционально)
if python3 -c "import scapy" 2>/dev/null; then
    echo -e "${GREEN}✓ scapy установлен (методы 2,3 доступны)${NC}"
else
    echo -e "${YELLOW}⚠ scapy не установлен (только метод 1)${NC}"
    echo "  Для установки: pip install scapy"
fi

# ─── Проверка Shizuku ───

HAVE_ROOT=false

# Проверяем root через su
if su -c "id" 2>/dev/null | grep -q "uid=0"; then
    HAVE_ROOT=true
    echo -e "${GREEN}✓ Root доступен (su)${NC}"
fi

# Проверяем Shizuku
if command -v rish &> /dev/null; then
    echo -e "${GREEN}✓ Shizuku rish доступен${NC}"
    # Shizuku rish даёт shell с adb-привилегиями (не полный root)
    # Для raw sockets и iptables нужен полный root
    if ! $HAVE_ROOT; then
        echo -e "${YELLOW}  ⚠ Shizuku даёт ADB-привилегии, не полный root${NC}"
        echo -e "${YELLOW}  ⚠ Методы 2,3 (NFQUEUE) могут не работать${NC}"
        echo -e "${YELLOW}  ⚠ Метод 1 (raw sockets) может не работать${NC}"
        echo -e "${YELLOW}  → Рекомендуется: --methods 1 с обычным сокетом${NC}"
    fi
elif [ -f "/data/local/tmp/rish" ]; then
    echo -e "${GREEN}✓ Shizuku rish найден в /data/local/tmp/${NC}"
else
    echo -e "${YELLOW}⚠ Shizuku не обнаружен${NC}"
    echo "  Установите Shizuku из Google Play или GitHub"
    echo "  https://github.com/RikkaApps/Shizuku"
fi

# ─── Создание конфига если нет ───

if [ ! -f "$CONFIG_FILE" ]; then
    echo
    echo -e "${YELLOW}Конфиг не найден, генерирую дефолтный...${NC}"
    python3 "$EVADER_SCRIPT" --init-config -c "$CONFIG_FILE"
    echo -e "${GREEN}✓ Создан $CONFIG_FILE${NC}"
    echo -e "${YELLOW}  Отредактируйте конфиг перед запуском:${NC}"
    echo "  nano $CONFIG_FILE"
    echo
fi

# ─── Запуск ───

echo
echo -e "${GREEN}Запускаю DPI Evader v3...${NC}"
echo "────────────────────────────────"

# Определяем команду запуска
if $HAVE_ROOT; then
    # С root
    exec su -c "python3 '$EVADER_SCRIPT' -c '$CONFIG_FILE' $*"
elif command -v rish &> /dev/null; then
    # Через Shizuku (ограниченные привилегии)
    echo -e "${YELLOW}Запуск через Shizuku (ограниченные привилегии)${NC}"
    exec rish -c "cd '$SCRIPT_DIR' && python3 '$EVADER_SCRIPT' -c '$CONFIG_FILE' --methods 1 --no-distractor $*"
else
    # Без привилегий — только то, что работает
    echo -e "${YELLOW}Запуск без привилегий (ограниченный функционал)${NC}"
    exec python3 "$EVADER_SCRIPT" -c "$CONFIG_FILE" --methods 1 $*
fi

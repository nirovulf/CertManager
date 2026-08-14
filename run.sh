#!/bin/bash

# Скрипт для запуска приложения учета сертификатов электронных подписей
# Проверяет окружение, создает venv, устанавливает зависимости и запускает приложение

set -e  # Остановить выполнение при ошибке

echo "=== Запуск приложения учета сертификатов электронных подписей ==="

# Проверка Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 не найден. Пожалуйста, установите Python 3.8 или выше."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "✅ Найден Python версии: $PYTHON_VERSION"

# Проверка версии Python (должна быть 3.8+)
MAJOR_VERSION=$(echo $PYTHON_VERSION | cut -d'.' -f1)
MINOR_VERSION=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [ "$MAJOR_VERSION" -lt 3 ] || ([ "$MAJOR_VERSION" -eq 3 ] && [ "$MINOR_VERSION" -lt 8 ]); then
    echo "❌ Требуется Python 3.8 или выше. Найдена версия: $PYTHON_VERSION"
    exit 1
fi

# Переход в директорию проекта
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Проверка, находится ли приложение в поддиректории cert_manager
if [ ! -f "app.py" ] && [ -d "cert_manager" ] && [ -f "cert_manager/app.py" ]; then
    echo "📁 Обнаружена структура проекта с поддиректорией cert_manager"
    cd cert_manager
fi

echo "📁 Рабочая директория: $(pwd)"

# Создание виртуального окружения
if [ ! -d "venv" ]; then
    echo "🔄 Создание виртуального окружения..."
    python3 -m venv venv
    echo "✅ Виртуальное окружение создано"
else
    echo "✅ Виртуальное окружение уже существует"
fi

# Активация виртуального окружения
echo "🔄 Активация виртуального окружения..."
source venv/bin/activate

# Обновление pip
echo "🔄 Обновление pip..."
pip install --upgrade pip --quiet

# Установка зависимостей
if [ -f "requirements.txt" ]; then
    echo "🔄 Установка зависимостей из requirements.txt..."
    pip install -r requirements.txt --quiet
    echo "✅ Зависимости установлены"
else
    echo "❌ Файл requirements.txt не найден"
    exit 1
fi

# Проверка наличия файла приложения
if [ ! -f "app.py" ]; then
    echo "❌ Файл app.py не найден"
    exit 1
fi

# Создание директории для загруженных файлов
mkdir -p uploads

# Запуск приложения
echo "🚀 Запуск приложения..."
echo "Приложение будет доступно по адресу: http://localhost:5000"
echo "Для остановки нажмите Ctrl+C"
python app.py

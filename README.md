# AeryxVPN JSON Parser

Генератор подписки AeryxVPN в формате JSON-массива для Happ/Xray. Каждый элемент `AeryxVPN.json` — отдельный профиль страны; дополнительный профиль `🇪🇺 Автовыбор` содержит все опубликованные узлы.

Общий профиль собирается из `config/xray-profile-template.json`, основанного на предоставленных рабочих конфигурациях Happ. Основные детали устройства, диагностики и запуска находятся в [README_RU.md](README_RU.md).

- Подписка: [`AeryxVPN.json`](AeryxVPN.json)
- Метаданные: [`AeryxVPN.metadata.json`](AeryxVPN.metadata.json) — не импортировать в Happ
- Тесты: `python -m unittest discover -s tests -v`

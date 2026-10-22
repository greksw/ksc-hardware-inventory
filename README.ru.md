# KSC Hardware Inventory — сбор физических модулей RAM

Проект объединяет **проверенный на одном Windows-компьютере** подход Kaspersky Security Center 15.1 Open API / Network Agent / NagRdu и переработанный публичный Python-клиент. Рабочий скрипт владельца послужил основой последовательности SDK; новая параметризованная версия **22.10.2026 успешно проверена на действующем KSC 15.1 и одном пилотном Windows-компьютере**: `preflight`, `probe` с TLS, `collect` и отдельный SSH-импорт в SQLite. Массовый запуск не проверялся.

Подробный [протокол ревизии исходного кода](REVIEW_NOTES.ru.md) фиксирует изменения и границы тестирования.

## Компоненты

| Путь | Назначение |
|---|---|
| `ksc_inventory/ksc_runner.py` | Клиент KSC API, строгая проверка хоста, Gateway, NagRdu, обработка результатов |
| `scripts/gateway_probe.py` | Только проверка GetCurrentHostState; не запускает программу на агенте |
| `scripts/ram_pilot.py` | Явно подтверждённый сбор RAM на **одном** компьютере |
| `ksc_inventory/result.py` | Ограниченная проверка KSC ZIP / JSON |
| `ksc_inventory/import_result.py` | Валидация и отдельная передача по ограниченному SSH (`--send`) |
| `collectors/ksc/utility/*` | Адаптированный KSC diagnostic ZIP-коллектор (CMD + PowerShell) |
| `collectors/windows/Collect-RamInventory.ps1` | Независимый read-only коллектор из PR #50; **другой путь возврата результата**, не NagRdu |
| `tools/build_ksc_collector.py` | Сборка KSC ZIP с именами ZIP-элементов через `/` |
| `tools/audit_publication.py`, `tests/` | Аудит потенциальных утечек и автономные тесты |

**Не входит:** закрытый KlAkOAPI SDK, реальные сертификаты, токены, SSH-ключи, GUID и отчёты. API-токен Inventory хранится **только на сервере приёма**.

## 1. Тесты без подключения к KSC

На Linux с Python 3.11+:

```bash
cd ~/projects/ksc-hardware-inventory
python3 -m unittest discover -s tests -v
python3 tools/audit_publication.py
```

В репозитории не должно быть содержимого `.venv`, `vendor`, каталогов `results`, частных `.env` и архивов отчётов. Внешние модули Python для офлайн-тестов не требуются.

## 2. Подключение Kaspersky SDK на управляющей машине

`KlAkOAPI` предоставляется установленным KSC; не публикуйте его в GitHub. В проверенной среде он подключался через `PYTHONPATH`:

```bash
cd ~/projects/ksc-hardware-inventory
source ~/projects/ksc-inventory/.venv/bin/activate
export PYTHONPATH="$PWD:$HOME/projects/ksc-inventory/vendor/SDK_DIRECTORY"
```

Если KSC доступен через SSH TCP-туннель к локальному `127.0.0.1:13299`, **URL Python должен использовать DNS-имя из SAN сертификата**, разрешающееся локально на `127.0.0.1`; туннель должен быть запущен отдельно. Не подменяйте проверку TLS флагом `verify=False`.

Доверенный CA — сертификат **издателя**, предварительно подтверждённый по другому защищённому каналу. После плановой ротации сертификатов KSC повторно проверьте цепочку доверия.

## 3. Конфигурация одного утверждённого компьютера

Значения ниже — фиктивные. Храните реальные значения в локальной оболочке/секретном файле вне Git и не публикуйте результаты команд с реальными GUID.

```bash
export KSC_URL='https://ksc.example.test:13299'
export KSC_CA_FILE="$HOME/.config/ksc-hardware-inventory/ksc-ca.pem"
export KSC_USER='ksc-inventory-user'
export KSC_TARGET_FQDN='pc-demo-01.example.test'
export KSC_EXPECTED_COMPUTER='PC-DEMO-01'
export KSC_EXPECTED_GUID='YOUR_APPROVED_HOST_GUID'
```

`KSC_EXPECTED_GUID` нужно заменить фактическим KSC Host ID соответствующего физического компьютера; невозможно выполнить живую проверку с этой заглушкой. По умолчанию используется **интерактивный ввод пароля** без записи его в код. Для отдельной службы возможен параметр `--password-file` с правами `0600` вне репозитория.

## 4. Подготовка KSC-коллектора

В отличие от standalone-коллектора из PR #50, эта версия записывает JSON также в каталог результатов, указанный Network Agent. ZIP состоит **строго** из `utility/Run-RamInventory.cmd` и `utility/Collect-RamInventory.ps1`.

```bash
python3 tools/build_ksc_collector.py \
  --cmd collectors/ksc/utility/Run-RamInventory.cmd \
  --ps1 collectors/ksc/utility/Collect-RamInventory.ps1 \
  --output "$HOME/ksc-ram-collector-reviewed.zip"

sha256sum "$HOME/ksc-ram-collector-reviewed.zip"
```

Запомните полученный SHA256 и указывайте его в явном параметре `--collector-sha256`. Коллектор адаптирован из раннего пилотного пакета, а не является побайтовой копией последнего рабочего ZIP. **Сначала тестируйте только один утверждённый хост.**

## 5. Три уровня запуска

Все команды выполняйте из корня проекта (`python -m ...`).

**A. Offline preflight: не подключается к KSC и ничего не исполняет**

```bash
python -m ksc_inventory.ksc_runner --mode preflight \
  --collector "$HOME/ksc-ram-collector-reviewed.zip"
```

**B. Проба Gateway: соединяется с KSC/Network Agent, НЕ запускает сбор**

```bash
python -m ksc_inventory.ksc_runner --mode probe
```

**C. Сбор: ЗАПУСКАЕТ PowerShell на одном целевом Windows-компьютере**

```bash
python -m ksc_inventory.ksc_runner --mode collect \
  --collector "$HOME/ksc-ram-collector-reviewed.zip" \
  --collector-sha256 '64_HEX_DIGITS_OF_APPROVED_ARCHIVE' \
  --confirm-computer "$KSC_EXPECTED_COMPUTER"
```

Нужно указать **реальный** SHA256 из `sha256sum`, а не текст примера. Без подтверждения имени компьютера, точного GUID и правильного SHA256 режим `collect` остановится **до KSC execution**. Результат сохраняется в приватный каталог `~/.local/share/ksc-hardware-inventory/results/` (режимы 0700/0600). На этом этапе **в Inventory API ничего не отправляется**.

## 6. Импорт уже сохранённого ZIP

```bash
python -m ksc_inventory.result /path/to/result.zip \
  --expected-computer "$KSC_EXPECTED_COMPUTER"

python -m ksc_inventory.import_result /path/to/result.zip \
  --expected-computer "$KSC_EXPECTED_COMPUTER" \
  --ssh-destination inventory-ingest@inventory.example.test \
  --identity "$HOME/.ssh/inventory_ingest_ed25519"
# По умолчанию DRY RUN; только после проверки ограниченного SSH — добавить --send.
```

Внутри полного `--mode collect` опция `--send` также требует `--ssh-destination` и `--identity` и включает **запись в Inventory API** после успешной проверки ZIP/JSON. На сервере `authorized_keys` должен принудительно запускать **только** root-owned импортёр через точечное `sudoers`, без аргументов; пользователь SSH — `inventory-ingest` и никогда `root`.

## 7. Контроль безопасности и публикация

- Не запускать массово: сбор до сих пор проверен через KSC только на одном эталонном узле.
- Токен SSH gateway не писать в лог. Не публиковать фактические GUID, Host IDs, DNS, JSON и Action IDs.
- В случае тайм-аута сохранить Action ID и **не повторять запуск автоматически**: задача на агенте может продолжаться.
- Для удалённого исполнения нужны высокие разрешения KSC в областях Connectivity и Common. Ограничивайте область доступа служебной записи.
- Проверяйте TLS при основном соединении и Gateway. После ротации сертификата требуется новая сверка.
- Перед публичным GitHub запускать аудит, тесты и **просмотреть весь `git diff --cached`**. Сканер секретов не является гарантией отсутствия утечек.

## Публикация проекта

Живой пробный запуск на одном утверждённом хосте **успешно выполнен 22.10.2026** ([протокол проверки](VALIDATION.ru.md)). Команды Git приведены в [README.md](README.md). Подтверждено: `preflight OK` → `probe OK` → `collect + ZIP validation OK` → отдельный `import_result --send` → новая запись в SQLite. **Комбинированный запуск `collect --send` и массовая обработка ещё не испытаны.**

Серия статей: [RAM-инвентаризация](https://notes.shandrov.ru/ru/notes/monitoring/ksc-openapi-ram-module-inventory/), [KSC RBAC 1184](https://notes.shandrov.ru/ru/notes/monitoring/ksc-openapi-nagrdu-1184-rbac/), [TLS и ограниченный SSH](https://notes.shandrov.ru/ru/notes/monitoring/ksc-openapi-verified-tls-inventory-ingest/).

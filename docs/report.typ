= Ход работы

== 1. Разработка функционального API

Создан учебный REST API на Python без внешних runtime-зависимостей. Для HTTP
слоя используется стандартный `http.server`, для хранения данных - SQLite.

Реализованы эндпоинты:
- `POST /auth/login` - проверяет логин и пароль, возвращает bearer-токен с
  ограниченным временем действия.
- `GET /api/data` - возвращает список публикаций, доступен только при наличии
  bearer-токена.
- `POST /api/posts` - создаёт новую публикацию от имени авторизованного
  пользователя.

Добавлены автоматические тесты для проверки работоспособности API,
аутентификации и запрета доступа без токена.

== 2. Внедрение базовых мер защиты

Для защиты от SQL-инъекций все обращения к SQLite выполняются через
параметризованные запросы с плейсхолдерами `?`. Пользовательский ввод не
склеивается с SQL-строками.

Для снижения риска XSS все строковые значения в JSON-ответах проходят через
`html.escape(..., quote: true)`. Это применяется централизованно перед отправкой
ответа клиенту и дополнительно при возврате данных из методов приложения.

Механизм аутентификации переведён на JWT. После успешного `POST /auth/login`
сервер выдаёт токен с `sub`, `username`, `iat` и `exp`, подписанный HMAC-SHA256.
Защищённые методы проверяют заголовок `Authorization: Bearer <token>`.

Пароли не хранятся в открытом виде. Для тестового пользователя пароль
хэшируется алгоритмом `scrypt` с солью; сравнение хэшей выполняется через
`hmac.compare_digest`.

== 3. Настройка CI/CD pipeline с security-сканерами

В проект добавлен GitHub Actions workflow `.github/workflows/ci.yml`.
Pipeline запускается при `push`, `pull_request` в ветку `main`, а также вручную
через `workflow_dispatch`.

Workflow состоит из трёх независимых job:
- `Tests` - устанавливает dev-зависимости и запускает `pytest`.
- `SAST Bandit` - запускает Bandit по каталогу `infosec_rest`, формирует
  `bandit-report.json` и сохраняет его как artifact.
- `SCA OWASP Dependency-Check` - запускает OWASP Dependency-Check по корню
  проекта, формирует HTML/JSON/XML-отчёты и сохраняет их как artifact
  `dependency-check-report`.

Для SAST добавлен конфигурационный файл `bandit.yaml`, исключающий тесты из
анализа. Для локального воспроизведения проверок добавлен
`requirements-dev.txt`. На Arch Linux зависимости устанавливаются в локальное
виртуальное окружение `.venv`, чтобы не изменять системный Python.

#figure(
  rect(width: 100%, height: 38mm, stroke: 1pt + gray, inset: 8pt)[
    *Вставить скриншот: общий успешный запуск workflow `CI` в GitHub Actions.*
    На скриншоте должны быть видны название workflow, зелёный статус и три job:
    `Tests`, `SAST Bandit`, `SCA OWASP Dependency-Check`.
  ],
  caption: [Скриншот успешного запуска CI pipeline],
)

#figure(
  rect(width: 100%, height: 38mm, stroke: 1pt + gray, inset: 8pt)[
    *Вставить скриншот: job `SAST Bandit` и artifact `bandit-report`.*
    Нужно открыть успешный запуск workflow, перейти в job Bandit и показать
    завершение шага `Run Bandit` без критических ошибок.
  ],
  caption: [Скриншот результата SAST-проверки Bandit],
)

#figure(
  rect(width: 100%, height: 38mm, stroke: 1pt + gray, inset: 8pt)[
    *Вставить скриншот: job `SCA OWASP Dependency-Check` и artifact
    `dependency-check-report`.* Нужно показать успешное выполнение Dependency-
    Check и наличие выгруженного отчёта в artifacts.
  ],
  caption: [Скриншот результата SCA-проверки OWASP Dependency-Check],
)

== 4. Тестирование и документирование

Работа API проверяется автоматическими тестами `pytest`. Тесты покрывают:
успешную аутентификацию, отказ при неверном пароле, защиту от SQL-инъекции при
логине, хранение пароля в виде `scrypt`-хэша, миграцию старой схемы,
создание публикации, экранирование пользовательского HTML и отклонение
подделанного JWT.

Для ручной проверки используются команды `curl`, приведённые в README:
получение токена через `POST /auth/login`, обращение к `GET /api/data` с
токеном и проверка отказа без заголовка `Authorization`.

Локально выполнены проверки:
- `.venv/bin/python -m pytest` - 9 тестов пройдены успешно.
- `.venv/bin/bandit -r infosec_rest -c bandit.yaml` - проблем не найдено.
- `GET /health` - получен `200 OK`.
- `GET /api/data` без токена - получен `401 Unauthorized`.
- `POST /auth/login` с тестовой учётной записью - получен JWT.
- `GET /api/data` с `Authorization: Bearer <token>` - получен `200 OK` и
  список публикаций.

#figure(
  rect(width: 100%, height: 40mm, stroke: 1pt + gray, inset: 8pt)[
    *Вставить скриншот: ручной тест `POST /auth/login`.*
    На скриншоте терминала должен быть ответ JSON с `access_token` и
    `token_type: Bearer`.
  ],
  caption: [Проверка получения JWT через curl],
)

#figure(
  rect(width: 100%, height: 40mm, stroke: 1pt + gray, inset: 8pt)[
    *Вставить скриншот: ручной тест доступа без токена.*
    Нужно выполнить `curl http://127.0.0.1:8000/api/data` и показать ответ
    `401` с ошибкой `Missing bearer token`.
  ],
  caption: [Проверка запрета доступа без JWT],
)

#figure(
  rect(width: 100%, height: 40mm, stroke: 1pt + gray, inset: 8pt)[
    *Вставить скриншот: ручной тест защищённого доступа с токеном.*
    Нужно передать `Authorization: Bearer <token>` и показать успешный ответ
    `GET /api/data` со списком публикаций.
  ],
  caption: [Проверка доступа к защищённому endpoint с JWT],
)

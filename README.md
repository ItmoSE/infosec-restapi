# infosec-restapi

Учебный REST API на Python для поэтапной реализации защищенного веб-сервиса.
Проект использует стандартную библиотеку Python и SQLite.

## Запуск

Создание локального виртуального окружения:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

Запуск сервера:

```bash
INFOSEC_ADMIN_PASSWORD=admin123 \
.venv/bin/python -m infosec_rest.server
```

По умолчанию API запускается на `http://127.0.0.1:8000`.
Пароль администратора задаётся через `INFOSEC_ADMIN_PASSWORD`. Если переменная
не указана и база создаётся впервые, пароль будет сгенерирован случайно.

## API

### `GET /health`

Проверка работоспособности сервиса.

```bash
curl http://127.0.0.1:8000/health
```

### `POST /auth/login`

Аутентификация пользователя. Тестовая учетная запись: `admin` / `admin123`.
При успешной проверке возвращается JWT access token.

```bash
curl -X POST http://127.0.0.1:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}'
```

### `GET /api/data`

Получение списка публикаций. Требует bearer-токен из `/auth/login`.

```bash
curl http://127.0.0.1:8000/api/data \
  -H "Authorization: Bearer <token>"
```

### `POST /api/posts`

Создание публикации. Требует bearer-токен.

```bash
curl -X POST http://127.0.0.1:8000/api/posts \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer <token>" \
  -d '{"title":"Second post","body":"Created through API"}'
```

## Реализованные меры защиты

### Защита от SQLi

Все SQL-запросы выполняются через параметризованные выражения SQLite:
пользовательские значения передаются отдельно от текста запроса через
плейсхолдеры `?`. Конкатенация строк для построения SQL-запросов не
используется.

### Защита от XSS

Перед отправкой JSON-ответа все строковые значения проходят через
`html.escape(..., quote=True)`. Это экранирует пользовательские данные,
которые возвращаются из API, включая заголовки и тексты публикаций.

### Аутентификация

`POST /auth/login` проверяет логин и пароль. Пароли не хранятся в открытом
виде: при инициализации тестовый пароль хэшируется алгоритмом `scrypt` с
криптографической солью. Проверка выполняется через `hmac.compare_digest`.

При успешном входе API выдаёт JWT с алгоритмом `HS256`, полями `sub`,
`username`, `iat` и `exp`. Защищенные эндпоинты проверяют заголовок
`Authorization: Bearer <token>` и отклоняют запросы без валидного токена.

## Тестирование и security-проверки

Локальный запуск автотестов:

```bash
.venv/bin/python -m pytest
```

Локальный запуск SAST:

```bash
.venv/bin/bandit -r infosec_rest -c bandit.yaml
```

CI/CD настроен в `.github/workflows/ci.yml`. Pipeline запускается при `push`,
`pull_request` в ветку `main` и вручную через `workflow_dispatch`.

В pipeline выполняются:
- `Tests` - запуск `pytest`.
- `SAST Bandit` - статический анализ Python-кода через Bandit, JSON-отчёт
  сохраняется в artifact `bandit-report`.
- `SCA OWASP Dependency-Check` - проверка зависимостей и компонентов проекта
  через OWASP Dependency-Check, отчёты сохраняются в artifact
  `dependency-check-report`.

## Скриншоты отчетов

После первого успешного запуска GitHub Actions нужно добавить сюда скриншоты:
- общий успешный запуск workflow `CI`;
- успешный job `SAST Bandit` и artifact `bandit-report`;
- успешный job `SCA OWASP Dependency-Check` и artifact
  `dependency-check-report`;
- страницу последнего успешного запуска pipeline, ссылку на которую нужно
  приложить при сдаче.

Для ручных скриншотов API нужно запустить сервер и выполнить команды из
раздела `API`: логин, запрос `/api/data` без токена и запрос `/api/data` с
полученным bearer-токеном.

# infosec-restapi

Учебный REST API на Python для поэтапной реализации защищенного веб-сервиса.

## Запуск

```bash
python -m infosec_rest.server
```

По умолчанию API запускается на `http://127.0.0.1:8000`.

## API

### `GET /health`

Проверка работоспособности сервиса.

```bash
curl http://127.0.0.1:8000/health
```

### `POST /auth/login`

Аутентификация пользователя. Тестовая учетная запись: `admin` / `admin123`.

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

Раздел будет расширяться по мере выполнения этапов защиты.

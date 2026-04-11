# StoneCrab

Минималистичный **WSGI-фреймворк** в одном файле [`stonecrab.py`](stonecrab.py): маршрутизация по приложениям `apps/*`, цепочка middleware, шаблоны, CLI (`startproject`, `startapp`, `runserver`), встроенный dev-сервер, OpenAPI/health, набор сетевых утилит на stdlib (`Utilities.Network`).

### Источники идеи

- [Bottle](https://github.com/bottlepy/bottle)
- [How to write a Python web framework. Part I](https://rahmonov.me/posts/write-python-framework-part-one/)
- [How to write a Python web framework. Part II](https://rahmonov.me/posts/write-python-framework-part-two/)
- [How to write a Python web framework. Part III](https://rahmonov.me/posts/write-python-framework-part-three/)
- [Пишем свой шаблонизатор на Python (Habr)](https://habr.com/ru/articles/180935/)

## Требования

- Python **3.9+** (рекомендуется актуальная ветка 3.x).

## Быстрый старт

1. Положите [`stonecrab.py`](stonecrab.py) в корень проекта (или добавьте каталог с ним в `PYTHONPATH`).
2. Сгенерируйте каркас:
   ```bash
   python3 stonecrab.py startproject
   ```
3. Запуск для разработки:
   ```bash
   python3 stonecrab.py runserver
   ```

## Демонстрационный сайт

В репозитории — приложение [`apps/index/`](apps/index/): сайт **библиотеки** на корне **`/`** (каталог книг с обложками, карточка по `id`, разделы по жанру `slug`, добавление книги классом `View`, примеры `uuid` и `hex2` в пути), читательский билет (сессия), вопрос библиотекарю, загрузка файла, страница «Сервис». Шаблоны — [`templates/index/`](templates/index/), стили и SVG-обложки — [`static/index/`](static/index/). Маршрут **`/service/ping/`** подключён только из словаря [`routes.urls`](apps/index/routes.py).

Запуск: `python3 stonecrab.py runserver`, в браузере **`http://127.0.0.1:8000/`**. В формах POST — скрытое поле `csrf_token`.

## Конфигурация

После `startproject` используется пакет [`settings/`](settings/): переменная окружения **`STONECRAB_ENV`** (`development` / `production`), см. [`settings/__init__.py`](settings/__init__.py).

Если пакет **`settings`** отсутствует, подставляется **заглушка** `types.SimpleNamespace`. Перехватывается только **`ModuleNotFoundError`** с именем `settings`; любая другая ошибка при импорте (синтаксис, отсутствующая зависимость внутри `settings`) **пробрасывается**.

Задайте **`SECRET_KEY`** в продакшене: от него зависит **подпись session-cookie** (HMAC-SHA256).

### Полезные флаги в `settings`

| Имя | Назначение |
|-----|------------|
| `DEBUG` | При `True` необработанные исключения в view дают **полный traceback** в теле ответа (500); в проде держите `False`. |
| `REQUEST_ID_TRUST_CLIENT` | Если `True`, берётся `X-Request-Id` из запроса (обрезка длины); иначе id всегда генерируется. |
| `RESPONSE_REQUEST_ID_HEADER` | Отдавать ли `X-Request-Id` в ответе (`RequestIdMiddleware`). |
| `CSP_USE_NONCE` | Добавить nonce к CSP (`script-src` с `'nonce-…'`); в шаблонах можно использовать `request.csp_nonce`. |
| `CONTENT_SECURITY_POLICY` | Своя строка CSP; иначе базовая из `SecurityMiddleware`. |
| `UPLOAD_FORBIDDEN_EXTENSIONS` | Кортеж суффиксов (`".exe"`, …): такие файлы в `multipart` отбрасываются, ответ **403**. |

## Маршрутизация

- Явные пары в `apps/<app>/routes.py`: словарь **`urls`**, путь → callable.
- Декоратор **`@route(path, methods=…, openapi=…)`** на функциях и классах в `views.py`; путь дополняется префиксом приложения (`URL_PREFIX`).

### Именованные параметры

1. **Фигурные скобки** — строка сегмента: `/user/{id}/`.
2. **Конвертеры** — `<str:name>`, `<int:pk>`, `<slug:s>`, `<uuid:id>`.

**Свой конвертер:** `register_path_converter("mytype", lambda raw: …)` — далее `<mytype:param>` в пути.

### OpenAPI

Второй аргумент декоратора: `openapi={"*": {"description": "…"}}` или по методу: `openapi={"get": {"responses": {…}}}}`. Сливается в спецификацию `/openapi.json`.

## Хуки жизненного цикла

- В **`settings`**: `BEFORE_REQUEST_HOOKS`, `AFTER_REQUEST_HOOKS` (списки вызываемых объектов).
- Программно: **`register_hook("before_request", fn)`** / **`register_hook("after_request", fn)`**; сброс **`clear_hooks()`** / **`clear_hooks("before_request")`**.

Обработка в **`RequestHooksMiddleware`** (списки из settings и глобальные объединяются).

## Middleware

Порядок в **`settings.MIDDLEWARE`**: **внешний слой первым** (ближе к клиенту). Классы должны быть определены в `stonecrab.py` (имена резолвятся через `globals()`).

В типовом `base` после `TrustedHost` идёт **`RequestIdMiddleware`** (id в логах и заголовке ответа).

## Сессия и cookie

- Данные сессии — **в памяти процесса** (`SESSION_STORE`). Несколько воркеров за балансировщиком **не разделяют** сессию автоматически; для общего состояния нужен внешний стор (Redis и т.п.) — подключать в проекте отдельно.
- С **`SECRET_KEY`** cookie сессии подписывается (`sid.hmac`).

## Шаблоны

Теги `{% %}`, `{{ }}`, **`render(template, context_dict)`** (контекст одним словарём вторым аргументом).

- **`{% extends "base.html" %}`** в начале дочернего файла, затем **`{% block имя %}…{% endblock %}`** — подстановка в родителе.
- **`{% include "partial.html" %}`** — вставка с тем же контекстом.

Локализация чисел/дат в шаблоне: форматируйте во view и передавайте в контекст готовые строки.

## Сеть (stdlib)

Класс **`Utilities.Network`**: TCP/TLS, UDP, FTP, HTTP (`urllib`), SMTP, системный `ping`.

## Деплой (gunicorn + nginx)

**Gunicorn** (пример, из каталога проекта, где есть `wsgi.py` и `settings`):

```bash
export STONECRAB_ENV=production
export STONECRAB_SECRET_KEY="$(openssl rand -hex 32)"
gunicorn -w 4 -b 127.0.0.1:8001 wsgi:application
```

**Nginx** (фрагмент прокси на gunicorn):

```nginx
location / {
    proxy_pass         http://127.0.0.1:8001;
    proxy_set_header   Host $host;
    proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;
}
```

Убедитесь, что **`ALLOWED_HOSTS`** соответствует реальным хостам, **`DEBUG = False`**, **`SECRET_KEY`** задан, HTTPS включает **`SESSION_COOKIE_SECURE`** при необходимости.

## Логи

**`log_event(event, **fields)`** пишет JSON в stderr. Поле **`request_id`** добавляется в **`http_access`** из middleware логирования.

# Дизайн: Batch Mode через HTTP Request Pipeline (§5.1)

- **Дата:** 2026-06-30
- **Статус:** утверждён к реализации
- **Источник:** `docs/COMPETITIVE_GAPS.md` §5.1 — Batch Mode Tools
- **Затрагивает компоненты:** Java-плагин (`src/main/java/...`), MCP-бридж (`bridge_mcp_hydra.py`). CLI в этой итерации **не** трогаем.

## 1. Контекст и цель

Каждый MCP-вызов сейчас — отдельный HTTP roundtrip и отдельная Ghidra-транзакция.
При документировании 50 функций агент делает 50× `functions_decompile`, 50× `functions_rename`
и т.д. Главный bottleneck AI-агентов на больших бинарниках — **число MCP-вызовов**, а не
качество анализа. Batch-режим устраняет это: один запрос выполняет массив операций.

**Цель:** добавить единый batch-эндпоинт, выполняющий массив «виртуальных» HTTP-запросов к
уже существующим контроллерам, и поверхность в MCP-бридже (генеричную + именованные обёртки).

### Принятые решения

| Решение | Выбор |
|---|---|
| Форма API | **HTTP Request Pipeline** (стиль Google API / OData `$batch`): единый `POST /batch`, принимающий массив под-запросов `{method, path, body}`, диспетчеризуемых на существующие хендлеры. |
| Семантика транзакции | **Best-effort по умолчанию**; опциональный флаг `atomic: true` → all-or-nothing. |
| Механизм диспетчеризации | **Реестр маршрутов + синтетический контекст** (in-process, без loopback-HTTP). |
| MCP-поверхность | **Генеричный `batch_execute` + именованные обёртки** из §5.1. |
| CLI | Не в этой итерации. |

### Почему именно так (ключевые обоснования)

- **Pipeline, а не 7 отдельных эндпоинтов** — на 100% сохраняет архитектуру «один маршрут —
  одна операция», автоматически делает batch-режим доступным для *любого* эндпоинта, не только
  для 7 из спецификации.
- **Best-effort по умолчанию** — толерантность к галлюцинациям LLM: батч из 50 переименований
  не падает целиком из-за одной опечатки в имени/адресе; агент получает массив с
  `success:false` у проблемного item и точечно исправляет.
- **`atomic:true` опционально** — для логически связанных последовательностей (создать struct →
  добавить vtable-поле → добавить поля данных), где «полуготовое» состояние недопустимо.

## 2. Архитектура (Java-плагин)

### Поток выполнения

```
POST /batch
  → BatchResource (route handler)
  → BatchService
      parse под-запросов
      [atomic? открыть одну outer-транзакцию : нет]
      for each request:
        RouteRegistry.match(method, path) → (handler, pathParams)
        построить SyntheticGhidraContext (pathParams, query, body)
        try: handler.accept(synthCtx)            // вызов существующего хендлера in-process
        catch: ErrorMapper.toError(e)            // тот же маппинг, что и middleware
        собрать CapturedResponse в result[index]
      [atomic & был сбой? endTransaction(commit=false)]
  → стандартный HATEOAS-конверт с массивом result
```

### Новые / изменённые элементы

| Элемент | Тип | Роль |
|---|---|---|
| `server/RouteRegistry.java` | new | Хранит список `(HandlerType method, String pattern, Consumer<GhidraContext> handler)`. `match(method, path)` сопоставляет путь с паттернами (поддержка сегментов `{address}`, `{name}`), извлекает path-параметры (с URL-decode) и query-string. |
| `server/Routes.java` | new | Тонкая обёртка над `Javalin app` + `contextFactory` + `RouteRegistry`. Методы `get/post/patch/put/delete(String path, Consumer<GhidraContext> handler)` **одновременно** регистрируют маршрут в Javalin (`app.<m>(path, ctx -> handler.accept(factory.apply(ctx)))`) и записывают `(method, pattern, handler)` в реестр. |
| `server/Resource.java` | change | Сигнатура `register(Javalin, Function<Context,GhidraContext>)` → `register(Routes routes)`. |
| `resource/*.java` (все) | mechanical | `app.post("/x", ctx -> h(factory.apply(ctx)))` → `routes.post("/x", this::h)`. Хендлеры уже имеют сигнатуру `void h(GhidraContext)` = `Consumer<GhidraContext>`, поэтому замена чисто механическая и попутно убирает бойлерплейт лямбды/factory. |
| `server/SyntheticGhidraContext.java` | new | Наследник `GhidraContext`. Переопределяет `pathParam/queryParam/queryParamAsInt/bodyAsClass/method/path` — отдаёт значения из под-запроса. Переопределяет `json(Object)`/`status(int)` — **перехватывает** в `CapturedResponse` вместо отправки в реальный HTTP-ответ. «Сырой» `Context` (для `Response.ok(ctx.ctx(), ...)` → `addMeta` → `header("X-Request-ID")`) отдаётся как лёгкий proxy, отвечающий только на `header(...)` (возвращает `null` → генерируется UUID). |
| `resource/BatchResource.java` | new | Регистрирует `POST /batch`, парсит тело, делегирует в `BatchService`, оборачивает результат в HATEOAS-конверт. |
| `service/BatchService.java` | new | Оркестрация цикла, транзакционная семантика (best-effort / atomic), сбор результатов. |
| `middleware/ErrorHandler` (+ helper) | refactor | Выделить маппинг `Exception → (status, errorCode, message)` в переиспользуемый метод (напр. `ErrorMapper.map(Exception)`), вызывать его из Javalin-обработчиков исключений **и** из `BatchService`, чтобы статусы под-запросов были консистентны с одиночными вызовами. |

> `GhidraContext` уже служит швом: хендлеры читают запрос и пишут ответ почти исключительно
> через его методы; «сырой» `io.javalin.http.Context` используется лишь для чтения заголовка
> `X-Request-ID` в `Response.addMeta`. Поэтому синтетический контекст реализуется дёшево.

### Сопоставление путей (`RouteRegistry.match`)

- Паттерн и путь делятся по `/`; число сегментов должно совпадать.
- Литеральные сегменты сравниваются как есть; сегмент вида `{name}` captures значение.
- Захваченные значения URL-декодируются (как это делает Javalin для `pathParam`).
- Хвостовая query-string (`?k=v&...`) парсится в map query-параметров.
- Нет совпадения → `BatchService` формирует item со `status: 404`, `code: "NO_ROUTE"`.

## 3. Формат запроса/ответа

### Запрос

```jsonc
POST /batch
{
  "atomic": false,                       // optional, default false
  "requests": [
    {"method": "GET",   "path": "/functions/by-name/main/decompile"},
    {"method": "PATCH", "path": "/functions/0x401000", "body": {"name": "parse_header"}},
    {"method": "POST",  "path": "/data",  "body": {"address": "0x40a0", "type": "char[16]"}}
  ]
}
```

### Ответ

```jsonc
{
  "success": true,            // состоялось ли выполнение батча (НЕ про каждый item)
  "result": [
    {"index": 0, "status": 200, "success": true,  "body": { /* конверт decompile */ }},
    {"index": 1, "status": 200, "success": true,  "body": { /* конверт rename   */ }},
    {"index": 2, "status": 400, "success": false, "body": { "error": {"code":"BAD_REQUEST", ...} }}
  ],
  "_links": {"self": {"href": "/batch"}}
}
```

- `result` — массив по порядку под-запросов; каждый элемент: `index`, `status`, `success`, `body`
  (полный конверт, который вернул бы одиночный вызов).
- В режиме `atomic:true` при первом сбое выполнение прекращается, внешняя транзакция
  откатывается; сбойный item помечается своей ошибкой, остальные (не выполненные/откатанные) —
  `status: 409`, `code: "ROLLED_BACK"`.

## 4. Транзакции и обработка ошибок

Опирается на **подтверждённую вложенность транзакций** в `util/TransactionHelper`
(`executeInTransaction` исполняется на EDT через `Swing.runNow`, реентерабельно; вложенный
`endTransaction` не считается сбоем — см. комментарии в коде).

- **best-effort (default):** outer-транзакция **не** открывается. Каждый под-запрос
  диспетчеризуется как обычный вызов — мутирующие хендлеры открывают собственную (внешнюю для
  себя) транзакцию через `executeInTransaction` и коммитятся/откатываются независимо. Сбой
  одного под-запроса не влияет на остальные. Read-операции (decompile, list) транзакцию не
  трогают.
- **atomic (opt-in):** весь цикл оборачивается в один `TransactionHelper.executeInTransaction`.
  Хендлеры вкладываются (nested). На первом сбое выполнение прекращается, внешняя транзакция
  закрывается с `commit=false` → Ghidra откатывает все изменения батча.
- Исключения каждого под-запроса ловятся в `BatchService` и конвертируются в error-конверт тем
  же маппингом, что и middleware: `NoProgramException`→503, `NoProjectException`→503,
  `NotFoundException`→404, `BadRequestException`/`IllegalArgumentException`/`JsonSyntaxException`→400,
  прочее→500.
- Неизвестный `(method, path)` → item со `status: 404`, `code: "NO_ROUTE"`.

> ⚠️ **Критично к проверке:** точное поведение вложенного отката в `atomic` (что `commit=false`
> на внешней транзакции откатывает изменения вложенных под-запросов) подтверждается интеграционным
> тестом mutate-then-revert (в духе `test_data_operations.py`).

## 5. MCP-обёртки (bridge)

- **Генеричный инструмент:**
  `batch_execute(requests: list[dict], atomic: bool = False, port: int | None = None)` — тонкая
  обёртка над `POST /batch` через `safe_post`; `simplify_response` чистит конверт.
- **Именованные обёртки** (каждая строит `requests` и зовёт `/batch`); суффикс `_batch`, чтобы не
  конфликтовать с существующими одиночными инструментами:
  - `functions_decompile_batch(names: list[str])`
  - `functions_rename_batch(renames: list[dict])` — элементы `{old, new}`
  - `data_create_batch(items: list[dict])` — `{address, type, name?}`
  - `data_set_type_batch(items: list[dict])` — `{address, type}`
  - `data_rename_batch(items: list[dict])` — `{address, name}`
  - `structs_add_field_batch(items: list[dict])`
  - `structs_update_field_batch(items: list[dict])`
- **Форматтер** `format_batch_results` для `@text_output` — компактная таблица
  `index | op | status | ok/err`.

## 6. Тестирование

- **Unit (`tests/`, без Ghidra) — TDD, до реализации:**
  - `RouteRegistry`: сопоставление путей, извлечение `{param}`, URL-decode, парсинг query-string,
    промах → отсутствие совпадения.
  - Парсинг тела `/batch` (валидное/невалидное).
  - `batch_execute` и именованные обёртки против fake-клиента — корректная сборка `requests`.
  - `format_batch_results`.
- **Integration (`test_*.py`, живая Ghidra, auto-skip без неё):** новый `test_batch.py`:
  - смешанный батч (decompile + rename + data_create), проверка порядка и частичных сбоев в
    best-effort;
  - atomic-rollback: мутация → намеренный сбой в середине → проверка полного отката, затем revert.

## 7. Версионирование и документация

- Бамп `PLUGIN_VERSION` (`api/ApiConstants.java`) и `BRIDGE_VERSION` (`bridge_mcp_hydra.py`).
  `API_VERSION` **не** трогаем — фича не ломает существующий API.
- `CHANGELOG.md` — пользовательское изменение.
- `GHIDRA_HTTP_API.md` — описание `POST /batch`.
- `README.md` — каталог новых MCP-инструментов.
- `docs/COMPETITIVE_GAPS.md` §5.1 → статус ✅ Done; обновить §0-трекер.

## 8. Вне объёма (YAGNI)

- CLI-команда `ghydra batch` — отдельная будущая итерация.
- Параллельное выполнение под-запросов — выполняем строго последовательно (одна EDT, порядок
  важен и для atomic, и для предсказуемости).
- Частичный/выборочный откат внутри atomic (только все-или-ничего).
- Вложенные/рекурсивные батчи (`/batch` внутри `/batch`) — запрещены: `NO_ROUTE` или явная ошибка.

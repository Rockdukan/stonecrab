import html
import json
import secrets

from stonecrab import View, render, register_path_converter, route

DEMO_SAMPLE_UUID = "550e8400-e29b-41d4-a716-446655440000"


def convert_hex2_segment(raw):
    s = (raw or "").lower()

    if len(s) == 2 and all(c in "0123456789abcdef" for c in s):
        return s
    raise ValueError("expected 2 hex digits")


register_path_converter("hex2", convert_hex2_segment)

BOOKS = [
    {
        "id": 1,
        "title": "Мастер и Маргарита",
        "author": "М. Булгаков",
        "year": 1967,
        "genre": "klassika",
        "synopsis": "Роман о добре и зле, любви и Москве тридцатых годов.",
        "cover": "/static/index/covers/1.svg",
    },
    {
        "id": 2,
        "title": "Понедельник начинается в субботу",
        "author": "А. и Б. Стругацкие",
        "year": 1965,
        "genre": "fantastika",
        "synopsis": "Научная фантастика и сатира о научном институте волшебства.",
        "cover": "/static/index/covers/2.svg",
    },
    {
        "id": 3,
        "title": "Чистый код",
        "author": "Р. Мартин",
        "year": 2008,
        "genre": "it",
        "synopsis": "Практики написания поддерживаемого программного кода.",
        "cover": "/static/index/covers/3.svg",
    },
    {
        "id": 4,
        "title": "1984",
        "author": "Дж. Оруэлл",
        "year": 1949,
        "genre": "klassika",
        "synopsis": "Антиутопия о тотальном контроле и новоязе.",
        "cover": "/static/index/covers/4.svg",
    },
    {
        "id": 5,
        "title": "Sapiens",
        "author": "Ю. Харари",
        "year": 2011,
        "genre": "nauka",
        "synopsis": "Краткая история человечества от эволюции до современности.",
        "cover": "/static/index/covers/5.svg",
    },
]
NEXT_BOOK_ID = 6
DEFAULT_COVER = "/static/index/covers/default.svg"


def render_json(response, data, status=200):
    response.status_code = status
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    response.text = json.dumps(data, ensure_ascii=False, indent=2)
    return response


def find_book(book_id):
    for b in BOOKS:

        if b["id"] == int(book_id):
            return b

    return None


def books_filtered(genre_slug=None):
    if not genre_slug:
        return list(BOOKS)

    return [b for b in BOOKS if b.get("genre") == genre_slug]


def book_cover_src(b):
    return html.escape(b.get("cover") or DEFAULT_COVER)


def html_featured_cards(books_slice):
    parts = []

    for b in books_slice:
        t = html.escape(b["title"])
        au = html.escape(b["author"])
        sy = html.escape(b["synopsis"])
        bid = int(b["id"])
        cov = book_cover_src(b)
        parts.append(
            '<article class="card card--book">'
            f'<a class="card-cover" href="/books/{bid}/"><img src="{cov}" width="140" height="210" alt=""></a>'
            f'<h2><a href="/books/{bid}/">{t}</a></h2>'
            f"<p>{au}, {b['year']}</p>"
            '<p class="footer-links" style="margin:0;border:0;padding:0;">'
            f"{sy}</p>"
            f'<a class="btn" href="/books/{bid}/">Подробнее</a>'
            "</article>"
        )

    return "".join(parts)


def html_genre_links(genres):
    items = []

    for g in genres:
        ge = html.escape(g)
        items.append(f'<li><a href="/genre/{ge}/">{ge}</a></li>')

    return "<ul>" + "".join(items) + "</ul>"


def html_book_table_rows(books):
    rows = []

    for b in books:
        t = html.escape(b["title"])
        au = html.escape(b["author"])
        g = html.escape(b["genre"])
        bid = int(b["id"])
        cov = book_cover_src(b)
        rows.append(
            "<tr>"
            f'<td class="td-cover"><img src="{cov}" width="48" height="72" alt=""></td>'
            f"<td>{bid}</td>"
            f'<td><a href="/books/{bid}/">{t}</a></td>'
            f"<td>{au}</td>"
            f"<td>{b['year']}</td>"
            f'<td><a href="/genre/{g}/">{g}</a></td>'
            "</tr>"
        )

    return "\n".join(rows)


def html_book_title_links(books):
    items = []

    for b in books:
        t = html.escape(b["title"])
        bid = int(b["id"])
        items.append(f'<li><a href="/books/{bid}/">{t}</a></li>')

    return "<ul>" + "".join(items) + "</ul>"


def from_urls_dict_only(request, response):
    return render(
        "index/service_ping.html",
        {"title": "Служебная страница", "message": "Маршрут подключён только из routes.urls."},
    )


@route("/")
def home(request, response):
    genres = sorted({b["genre"] for b in BOOKS})
    return render(
        "index/home.html",
        {
            "title": "Главная",
            "featured_cards_html": html_featured_cards(BOOKS[:3]),
            "genres_html": html_genre_links(genres),
            "demo_uuid": DEMO_SAMPLE_UUID,
        },
    )


@route("/books/")
def book_catalog(request, response):
    return render(
        "index/books_list.html",
        {
            "title": "Каталог",
            "books_table_rows_html": html_book_table_rows(BOOKS),
            "heading": "Все издания",
        },
    )


@route("/genre/<slug:genre_slug>/")
def books_by_genre(request, response, genre_slug=None):
    items = books_filtered(genre_slug)

    if not items:
        response.status_code = 404
        response.headers["Content-Type"] = "text/plain; charset=utf-8"
        response.text = "Раздел не найден или пуст."
        return response

    return render(
        "index/books_list.html",
        {
            "title": f"Жанр: {genre_slug}",
            "books_table_rows_html": html_book_table_rows(items),
            "heading": f"Жанр: {genre_slug}",
        },
    )


@route("/books/doc/<uuid:u>/")
def book_uuid_demo(request, response, u=None):
    return render(
        "index/book_uuid_demo.html",
        {
            "title": "Справка по UUID",
            "uuid_value": html.escape(u),
        },
    )


@route("/books/<int:book_id>/")
def book_detail(request, response, book_id=None):
    b = find_book(book_id)

    if not b:
        response.status_code = 404
        response.headers["Content-Type"] = "text/plain; charset=utf-8"
        response.text = "Книга не найдена."
        return response

    cov = book_cover_src(b)
    safe = {
        "id": b["id"],
        "year": b["year"],
        "title": html.escape(b["title"]),
        "author": html.escape(b["author"]),
        "genre": html.escape(b["genre"]),
        "synopsis": html.escape(b["synopsis"]),
        "cover_src": cov,
    }
    return render(
        "index/book_detail.html",
        {"title": b["title"], "book": safe},
    )


@route("/shelf/<hex2:shelf_code>/")
def shelf_by_code(request, response, shelf_code=None):
    return render(
        "index/shelf_hex.html",
        {
            "title": f"Полка {shelf_code}",
            "code": shelf_code,
            "book_list_html": html_book_title_links(BOOKS),
        },
    )


@route("/books/add/", methods=("GET", "POST", "HEAD", "OPTIONS"))
class BookAdd(View):
    def get(self, request, response, **kwargs):
        return render(
            "index/book_add.html",
            {
                "title": "Новая книга",
                "csrf_token": request.csrf_token,
                "error_block": "",
            },
        )

    def post(self, request, response, **kwargs):
        global NEXT_BOOK_ID

        title = (request.POST.get("title") or "").strip()
        author = (request.POST.get("author") or "").strip()
        year_s = (request.POST.get("year") or "").strip()
        genre = (request.POST.get("genre") or "").strip().lower().replace(" ", "-")
        synopsis = (request.POST.get("synopsis") or "").strip()

        if not title or not author or not year_s.isdigit() or not genre:
            msg = html.escape(
                "Заполните название, автора, год (число) и жанр (латиница, дефис)."
            )
            return render(
                "index/book_add.html",
                {
                    "title": "Новая книга",
                    "csrf_token": request.csrf_token,
                    "error_block": f'<p class="pre" style="color:#f87171;">{msg}</p>',
                },
            )

        new_id = NEXT_BOOK_ID
        NEXT_BOOK_ID += 1
        BOOKS.append(
            {
                "id": new_id,
                "title": title,
                "author": author,
                "year": int(year_s),
                "genre": genre,
                "synopsis": synopsis or "Описание появится позже.",
                "cover": DEFAULT_COVER,
            }
        )
        return response.redirect(f"/books/{new_id}/", status_code=303)


@route(
    "/openapi-sample/",
    openapi={
        "get": {
            "summary": "Пример операции в OpenAPI",
            "responses": {"200": {"description": "текст"}},
        }
    },
)
def openapi_sample(request, response):
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.text = "Строка для спецификации /openapi.json"
    return response


@route("/redirect-example/")
def redirect_example(request, response):
    return response.redirect("/books/", status_code=302)


@route("/api/session/", methods=("GET",))
def session_api(request, response):
    pub = {k: v for k, v in request.session.items() if not str(k).startswith("_")}
    return render_json(response, {"session": pub, "session_id": request.session_id})


@route("/auth/demo/")
def auth_demo(request, response):
    request.session["demo_user_name"] = "Читатель (демо)"
    return response.redirect("/account/", status_code=302)


@route("/account/", methods=("GET", "POST"))
def account(request, response):
    if request.method == "POST":
        name = (request.POST.get("display_name") or "").strip()

        if name:
            request.session["demo_user_name"] = name

    n = int(request.session.get("library_visit_count", 0)) + 1
    request.session["library_visit_count"] = n
    display = (request.session.get("demo_user_name") or "").strip()
    return render(
        "index/account.html",
        {
            "title": "Читательский билет",
            "csrf_token": request.csrf_token,
            "visit_count": n,
            "demo_user": display or "— не указано —",
            "display_name": display,
        },
    )


@route("/contact/", methods=("GET", "POST"))
def contact(request, response):
    if request.method == "GET":
        return render(
            "index/contact.html",
            {
                "title": "Вопрос библиотекарю",
                "csrf_token": request.csrf_token,
                "subject": "",
                "body": "",
            },
        )

    lines = [
        f"GET = {request.GET!r}",
        f"POST = {request.POST!r}",
    ]
    return render(
        "index/contact_done.html",
        {"title": "Отправлено", "result_text": "\n".join(lines)},
    )


@route("/media/", methods=("GET", "POST"))
def media(request, response):
    if request.method == "GET":
        return render(
            "index/media.html",
            {"title": "Загрузка обложки", "csrf_token": request.csrf_token},
        )

    if request.upload_rejected_reason:
        response.status_code = 403
        return render(
            "index/media_done.html",
            {
                "title": "Отклонено",
                "result_json": request.upload_rejected_reason,
            },
        )

    files_info = {
        k: {"filename": (v or {}).get("filename"), "content_type": (v or {}).get("content_type")}
        for k, v in request.FILES.items()
    }
    payload = {"POST": request.POST, "FILES": files_info}
    return render(
        "index/media_done.html",
        {
            "title": "Файл получен",
            "result_json": json.dumps(payload, ensure_ascii=False, indent=2),
        },
    )


@route("/developer/")
def developer(request, response):
    return render("index/developer.html", {"title": "Сервис"})


@route("/boom/")
def boom(request, response):
    raise RuntimeError("намеренная ошибка (см. DEBUG в settings)")


@route("/idempo-echo/", methods=("POST",))
def idempo_echo(request, response):
    token = secrets.token_hex(8)
    return render_json(response, {"token": token, "path": request.path})


@route("/metrics-check/")
def metrics_check(request, response):
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.text = "Смотрите заголовок X-Response-Time-Ms"
    return response

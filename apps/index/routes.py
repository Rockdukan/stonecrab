from . import views

urls = {
    "/service/ping/": views.from_urls_dict_only,
}

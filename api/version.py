import connexion


def search():
    print(connexion.context['token_info'])
    return "search - Hello, VERSION"

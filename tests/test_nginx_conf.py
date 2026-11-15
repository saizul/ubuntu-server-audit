from hosts import fixture
from ubuntu_server_audit import nginx_conf


def test_tokenize_quotes_and_comments():
    tokens = nginx_conf.tokenize('location ~ "\\.php$" { # c\n add_header X "a;b"; }')
    assert tokens == ["location", "~", "\\.php$", "{", "add_header", "X", "a;b", ";", "}"]


def test_load_from_dump_with_includes_and_contexts():
    config = nginx_conf.load_from_dump(fixture("nginx-T-hardened.txt"))
    assert config.files[0] == "/etc/nginx/nginx.conf"
    assert "/etc/nginx/sites-enabled/example.com" in config.files
    tokens = config.find("server_tokens")
    assert tokens[0].args == ("off",) and tokens[0].context == ("http",)
    root = config.find("root")[0]
    assert root.args == ("/var/www/example.com/public",) and root.context == ("http", "server")
    assert nginx_conf.listens_with_tls(config)
    # includes that are not in the dump (snippets) are reported, not fatal
    assert any("snippets/fastcgi-php.conf" in e for e in config.errors)


def test_load_from_files():
    files = {
        "/etc/nginx/nginx.conf": "http { include conf.d/*.conf; include /etc/nginx/sites-enabled/*; }",
        "/etc/nginx/conf.d/a.conf": "server_tokens build;",
        "/etc/nginx/sites-enabled/site": "server { listen 80; ssl on; }",
    }
    config = nginx_conf.load(
        "/etc/nginx/nginx.conf",
        files.get,
        lambda pattern: [p for p in files if __import__("fnmatch").fnmatch(p, pattern)],
    )
    assert config.find("server_tokens")[0].context == ("http",)
    assert nginx_conf.listens_with_tls(config)  # "ssl on;" (old syntax)
    assert len(config.files) == 3


def test_include_loop_is_limited():
    files = {"/etc/nginx/nginx.conf": "include /etc/nginx/nginx.conf;"}
    config = nginx_conf.load("/etc/nginx/nginx.conf", files.get, lambda p: [p])
    assert config.errors


def test_empty_dump():
    assert nginx_conf.load_from_dump("nginx: test failed").errors
    assert nginx_conf.split_dump("# configuration file /a:\nx;\n# configuration file /b:\ny;\n") == {
        "/a": "x;",
        "/b": "y;",
    }

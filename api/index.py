# -*- coding: utf-8 -*-
import re
import requests
from flask import Flask, Response, redirect, request
from requests.exceptions import (
    ChunkedEncodingError,
    ContentDecodingError, ConnectionError, StreamConsumedError)
from requests.utils import (
    stream_decode_response_unicode, iter_slices, CaseInsensitiveDict)
from urllib3.exceptions import (
    DecodeError, ReadTimeoutError, ProtocolError)
from urllib.parse import quote

# 配置项
jsdelivr = 0
size_limit = 1024 * 1024 * 1024 * 999  # 999GB

white_list = '''
'''
black_list = '''
'''
pass_list = '''
'''

# 初始化白黑名单
white_list = [tuple([x.replace(' ', '') for x in i.split('/')]) for i in white_list.split('\n') if i]
black_list = [tuple([x.replace(' ', '') for x in i.split('/')]) for i in black_list.split('\n') if i]
pass_list = [tuple([x.replace(' ', '') for x in i.split('/')]) for i in pass_list.split('\n') if i]

# Flask 应用初始化
app = Flask(__name__)
CHUNK_SIZE = 1024 * 10
ASSET_URL = 'https://hunshcn.github.io/gh-proxy'

# 预加载资源
# index_html = requests.get(ASSET_URL, timeout=10).text
# icon_r = requests.get(ASSET_URL + '/favicon.ico', timeout=10).content
index_html = None
icon_r = None

def get_index_html():
    global index_html
    if index_html is None:
        index_html = requests.get(ASSET_URL, timeout=10).text
    return index_html

def get_icon():
    global icon_r
    if icon_r is None:
        icon_r = requests.get(ASSET_URL + '/favicon.ico', timeout=10).content
    return icon_r

# 正则匹配 GitHub 各类 URL
exp1 = re.compile(r'^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:releases|archive)/.*$')
exp2 = re.compile(r'^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:blob|raw)/.*$')
exp3 = re.compile(r'^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:info|git-).*$')
exp4 = re.compile(r'^(?:https?://)?raw\.(?:githubusercontent|github)\.com/(?P<author>.+?)/(?P<repo>.+?)/.+?/.+$')
exp5 = re.compile(r'^(?:https?://)?gist\.(?:githubusercontent|github)\.com/(?P<author>.+?)/.+?/.+$')

# 禁用默认请求头生成
requests.sessions.default_headers = lambda: CaseInsensitiveDict()


@app.route('/')
def index():
    if 'q' in request.args:
        return redirect('/' + request.args.get('q'))
    return get_index_html()

@app.route('/favicon.ico')
def icon():
    return Response(get_icon(), content_type='image/vnd.microsoft.icon')



def iter_content(self, chunk_size=1, decode_unicode=False):
    def generate():
        if hasattr(self.raw, 'stream'):
            try:
                for chunk in self.raw.stream(chunk_size, decode_content=False):
                    yield chunk
            except ProtocolError as e:
                raise ChunkedEncodingError(e)
            except DecodeError as e:
                raise ContentDecodingError(e)
            except ReadTimeoutError as e:
                raise ConnectionError(e)
        else:
            while True:
                chunk = self.raw.read(chunk_size)
                if not chunk:
                    break
                yield chunk
        self._content_consumed = True

    if self._content_consumed and isinstance(self._content, bool):
        raise StreamConsumedError()
    elif chunk_size is not None and not isinstance(chunk_size, int):
        raise TypeError("chunk_size must be an int, it is instead a %s." % type(chunk_size))

    reused_chunks = iter_slices(self._content, chunk_size)
    stream_chunks = generate()
    chunks = reused_chunks if self._content_consumed else stream_chunks

    if decode_unicode:
        chunks = stream_decode_response_unicode(chunks, self)
    return chunks


def check_url(u):
    for exp in (exp1, exp2, exp3, exp4, exp5):
        m = exp.match(u)
        if m:
            return m
    return False


@app.route('/<path:u>', methods=['GET', 'POST'])
def handler_func(u):
    u = u if u.startswith('http') else 'https://' + u
    if u.rfind('://', 3, 9) == -1:
        u = u.replace('s:/', 's://', 1)

    pass_by = False
    m = check_url(u)
    if m:
        m = tuple(m.groups())
        if white_list:
            for i in white_list:
                if m[:len(i)] == i or (i[0] == '*' and len(m) == 2 and m[1] == i[1]):
                    break
            else:
                return Response('Forbidden by white list.', status=403)
        for i in black_list:
            if m[:len(i)] == i or (i[0] == '*' and len(m) == 2 and m[1] == i[1]):
                return Response('Forbidden by black list.', status=403)
        for i in pass_list:
            if m[:len(i)] == i or (i[0] == '*' and len(m) == 2 and m[1] == i[1]):
                pass_by = True
                break
    else:
        return Response('Invalid input.', status=403)

    if (jsdelivr or pass_by) and exp2.match(u):
        u = u.replace('/blob/', '@', 1).replace('github.com', 'cdn.jsdelivr.net/gh', 1)
        return redirect(u)
    elif (jsdelivr or pass_by) and exp4.match(u):
        u = re.sub(r'(\.com/.*?/.+?)/(.+?/)', r'\1@\2', u, 1)
        _u = u.replace('raw.githubusercontent.com', 'cdn.jsdelivr.net/gh', 1)
        u = u.replace('raw.github.com', 'cdn.jsdelivr.net/gh', 1) if _u == u else _u
        return redirect(u)
    else:
        if exp2.match(u):
            u = u.replace('/blob/', '/raw/', 1)
        if pass_by:
            url = u + request.url.replace(request.base_url, '', 1)
            if url.startswith('https:/') and not url.startswith('https://'):
                url = 'https://' + url[7:]
            return redirect(url)
        u = quote(u, safe='/:')
        return proxy(u)


def proxy(u, allow_redirects=False):
    headers = {}
    r_headers = dict(request.headers)
    r_headers.pop('Host', None)
    try:
        url = u + request.url.replace(request.base_url, '', 1)
        if url.startswith('https:/') and not url.startswith('https://'):
            url = 'https://' + url[7:]
        r = requests.request(method=request.method, url=url, data=request.data,
                             headers=r_headers, stream=True, allow_redirects=allow_redirects)
        headers = dict(r.headers)

        if 'Content-length' in r.headers and int(r.headers['Content-length']) > size_limit:
            return redirect(u + request.url.replace(request.base_url, '', 1))

        def generate():
            for chunk in iter_content(r, chunk_size=CHUNK_SIZE):
                yield chunk

        if 'Location' in r.headers:
            _location = r.headers.get('Location')
            if check_url(_location):
                headers['Location'] = '/' + _location
            else:
                return proxy(_location, True)

        return Response(generate(), headers=headers, status=r.status_code)
    except Exception as e:
        headers['content-type'] = 'text/html; charset=UTF-8'
        return Response('server error ' + str(e), status=500, headers=headers)


# ✅ 关键：为 Vercel 提供 handler 变量
handler = app

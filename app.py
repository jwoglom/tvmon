#!/usr/bin/env python3
import os, time

from flask import Flask, render_template, Response, request, abort

from selenium.webdriver import Firefox
from selenium.webdriver.firefox.options import Options

import requests
from urllib.parse import urljoin

import time

class TimedSet(set):
    def __init__(self):
        self.__table = {}
    def add(self, item, timeout=300):
        self.__table[item] = time.time() + timeout
        set.add(self, item)
    def __contains__(self, item):
        if set.__contains__(self, item):
            if time.time() < self.__table.get(item):
                return True
            del self.__table[item]
            self.remove(item)
        return False
    def __iter__(self):
        for item in set.__iter__(self):
            if self.__contains__(item):
                yield item

app = Flask(__name__)

m3u8s = {}
allowed_proxy_urls = TimedSet()
domain = os.getenv('DOMAIN')

@app.route('/')
def index():
    return render_template('index.html', proxy="false")

@app.route('/proxy')
def index_proxy():
    return render_template('index.html', proxy="true")

@app.route('/m3u8s/<path:streams>')
def m3u8s_route(streams):
    print('streams:', streams)

    out = {}
    if len(m3u8s) == 0:
        for s in streams.split(','):
            if not s in m3u8s:
                m3u8s[s] = get_m3u8(s)

            out[s] = m3u8s[s]
    
    return out

@app.route('/m3u8/<path:s>')
def m3u8_route(s):
    print('stream:', s)

    out = {}

    if not s in m3u8s:
        m3u8s[s] = get_m3u8(s)

    out[s] = m3u8s[s]
    
    print('returning:', s)
    return out

def proxy_url_for(url):
    return urljoin(request.base_url, '/proxy_url?url=%s' % url)

def rewrite_m3u8(raw, url):
    out = []
    for line in raw.splitlines():
        if line.startswith('#') or line.startswith('http'):
            out.append(line)
        else:
            pu = proxy_url_for(urljoin(url, line))
            allowed_proxy_urls.add(urljoin(url, line))
            out.append(pu)
    return '\n'.join(out)

@app.route('/proxy_url')
def proxy_url_route():
    url = request.args.get('url')
    if url not in allowed_proxy_urls:
        abort(403, description="Disallowed proxy URL")
        return

    r = requests.get(url, headers={'referer': 'http://%s' % domain})
    ct = r.headers['content-type']
    if ct.lower() == 'application/vnd.apple.mpegurl':
        return Response(rewrite_m3u8(r.text, url), mimetype=ct)
    return Response(r.text, mimetype=ct)

@app.route('/m3u8_proxy/<path:s>')
def m3u8_proxy_route(s):
    print('stream:', s)

    if not s in m3u8s:
        m3u8s[s] = get_m3u8(s)

    r = requests.get(m3u8s[s], headers={'referer': 'http://%s' % domain})
    
    print('returning direct m3u8:', s)
    return Response(rewrite_m3u8(r.text, m3u8s[s]), mimetype=r.headers['content-type'])

@app.route('/expire/<path:s>')
def expire(s):
    print('expire:', s)
    if s in m3u8s:
        del m3u8s[s]
        print('deleted', s)
        return 'deleted'

    return ''

@app.route('/expire_all')
def expire_all():
    print('expire_all')
    count = 0
    for s in list(m3u8s):
        del m3u8s[s]
        print('deleted', s)
        count += 1

    return 'deleted {}'.format(count)

def get_m3u8(stream):
    opts = Options()
    opts.headless = True

    driver_url = 'https://%s/%s' % (domain, stream)
    print("Starting webdriver: %s" % driver_url)

    driver = Firefox(options=opts)

    def get_player_ids():
        return driver.execute_script("ids = []; document.querySelectorAll('.jwplayer').forEach(function(e) { ids.push(e.id); }); return ids")

    def get_jwplayer_url(id):
        exists = driver.execute_script("return typeof(jwplayer)")
        if exists == "undefined":
            print("undefined jwplayer!")
        f = driver.execute_script("return jwplayer('%s').getPlaylist()[0].file" % id)
        if f:
            print('found m3u8:', f)
            if f.startswith('https:///'):
                f = f.replace('https:///', 'https://%s/' % domain)
            return f
        
        return None

    try:
        driver.get(driver_url)
        print("Page loaded: %s" % driver_url)
        jwplayers = get_player_ids()
        if len(jwplayers) == 1:
            url = get_jwplayer_url(jwplayers[0])
            if url:
                return url
            
        seq = driver.find_elements_by_tag_name('iframe')
        for index in range(len(seq)):
            driver.switch_to_default_content()
            iframe = driver.find_elements_by_tag_name('iframe')[index]
            print('iframe:', iframe)
            driver.switch_to.frame(iframe)
            try:
                id = 'player'
                jwplayers = get_player_ids()
                if len(jwplayers) == 1:
                    id = jwplayers[0]
                url = get_jwplayer_url(id)
                if url:
                    return url

            except Exception as e:
                print('exception:', e)
                pass
    finally:
        driver.quit()
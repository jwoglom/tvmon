#!/usr/bin/env python3
import os, time

from flask import Flask, render_template, Response, request, abort

from selenium.webdriver import Firefox, FirefoxProfile
from selenium.webdriver.firefox.options import Options
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By

import requests
from urllib.parse import urljoin

import time
import os, os.path

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

ublock_xpi = 'ublock.xpi'
UBLOCK_XPI_URL = 'https://github.com/gorhill/uBlock/releases/download/1.32.5rc3/uBlock0_1.32.5rc3.firefox.signed.xpi'

if not os.path.exists(ublock_xpi):
    print("Downloading uBlock extension...")
    with open(ublock_xpi, 'wb') as f:
        f.write(requests.get(UBLOCK_XPI_URL).content)

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

    fp = FirefoxProfile()
    fp.set_preference("media.volume_scale", "0.0")

    driver_url = 'https://%s/%s' % (domain, stream)
    print("Starting webdriver: %s" % driver_url)

    driver = Firefox(options=opts, firefox_profile=fp)
     
    print("Installing ublock..")
    driver.install_addon(os.path.join(os.getcwd(), ublock_xpi), temporary=True)
    print("Done installing")

    def click_play_button():
        try:
            WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.CSS_SELECTOR, '.stream-single-center-message-box > span')))
            play_button = driver.find_element_by_css_selector(".stream-single-center-message-box > span")
            if play_button:
                play_button.click()
                print("clicked play button")
                time.sleep(1)
        except NoSuchElementException:
            print("no play button")

    def get_jwplayer_url():
        try:
            ids = driver.execute_script("ids = []; document.querySelectorAll('.jwplayer').forEach(function(e) { ids.push(e.id); }); return ids")
            if not ids:
                print("no jwplayers")
                return None
            id = ids[0]
            exists = driver.execute_script("return typeof(jwplayer)")
            if exists == "undefined":
                print("undefined jwplayer!")
                return None
            f = driver.execute_script("return jwplayer('%s').getPlaylist()[0].file" % id)
            if f:
                print('found m3u8:', f)
                if f.startswith('https:///'):
                    f = f.replace('https:///', 'https://%s/' % domain)
                return f
        except Exception as e:
            print("exception", e)
        
        return None
    
    def get_clappr_url():
        try:
            exists = driver.execute_script("return typeof(player)")
            if exists == "undefined":
                print("undefined clappr!")
                return None
            f = None
            for i in range(3):
                f = driver.execute_script("return typeof(player.options) != 'undefined' ? player.options.source : ''")
                if f != "":
                    break
                time.sleep(1)
            if f:
                print('found m3u8:', f)
                if f.startswith('https:///'):
                    f = f.replace('https:///', 'https://%s/' % domain)
                return f
        except Exception as e:
            print("exception", e)

        return None

    try:
        driver.get(driver_url)
        print("Page loaded: %s" % driver_url)

        click_play_button()

        url = get_jwplayer_url()
        if url:
            return url
        else:
            url = get_clappr_url()
            if url:
                return url

        seq = driver.find_elements_by_tag_name('iframe')
        for index in range(len(seq)):
            driver.switch_to_default_content()
            iframe = driver.find_elements_by_tag_name('iframe')[index]
            print('iframe:', iframe)
            driver.switch_to.frame(iframe)
            try:
                url = get_jwplayer_url()
                if url:
                    return url
                else:
                    url = get_clappr_url()
                    if url:
                        return url

            except Exception as e:
                print('exception:', e)
                pass
    finally:
        driver.quit()
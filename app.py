#!/usr/bin/env python3
import os, time

from flask import Flask, render_template, Response, request, abort, redirect

from prometheus_flask_exporter import PrometheusMetrics
from prometheus_client import Counter, Histogram

from selenium.webdriver import Firefox, FirefoxProfile
from selenium.webdriver.firefox.options import Options
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By

from bs4 import BeautifulSoup

import requests
from urllib.parse import urljoin, urlparse

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
metrics = PrometheusMetrics(app)

requested_m3u8_streams = Counter('requested_m3u8_streams', 'Requested m3u8 streams', ['domain', 'stream', 'https'])
fetched_m3u8_streams = Counter('fetched_m3u8_streams', 'Fetched m3u8 streams via webdriver', ['domain', 'stream', 'https'])
proxied_m3u8_streams = Counter('proxied_m3u8_streams', 'Proxied m3u8 stream urls', ['domain', 'stream', 'proxy_domain', 'https'])
proxied_m3u8_clips = Counter('proxied_m3u8_clips', 'Proxied m3u8 stream clips', ['domain', 'stream', 'proxy_domain', 'https'])
invalid_proxy_domains = Counter('invalid_proxy_domains', 'Invalid proxy domains', ['domain', 'stream', 'proxy_domain', 'https'])
get_m3u8_time = Histogram('get_m3u8_time', 'Time to fetch a m3u8', ['domain', 'stream'])

m3u8s = {}
allowed_proxy_domains = TimedSet()
domain_raw = os.getenv('DOMAIN')
domain = domain_raw
if 'http' in domain_raw:
    domain = urlparse(domain_raw).netloc
firefox_binary = os.getenv('FIREFOX_BINARY')
proxy_is_https = os.getenv('PROXY_IS_HTTPS')

def is_https():
    cf_https = request.headers.get('CF-Visitor') and 'https' in request.headers.get('CF-Visitor')
    return bool(proxy_is_https or cf_https)


ublock_xpi = 'ublock.xpi'
UBLOCK_RELEASES = 'https://github.com/gorhill/uBlock/releases'

def check_ublock_xpi():
    if not os.path.exists(ublock_xpi):
        print("Downloading uBlock extension...")
        r = requests.get(UBLOCK_RELEASES)
        if r.status_code/100 == 2:
            s = BeautifulSoup(r.text)
            for item in s.select('a'):
                link = item.get('href')
                if link.endswith('.firefox.signed.xpi'):
                    print("ublock.xpi link:", link)
                    rx = requests.get(link)
                    if rx.status_code/100 == 2:
                        with open(ublock_xpi, 'wb') as f:
                            f.write(rx.content)
                            print("wrote ublock xpi")
                            break
                    else:
                        print("error xpi:", rx.status_code)
        else:
            print("error:", r.status_code, r.text)
    print("uBlock xpi status:", os.path.exists(ublock_xpi))

check_ublock_xpi()

@app.route('/')
def index():
    return render_template('index.html', proxy="false")

@app.route('/proxy')
def index_proxy():
    return render_template('index.html', proxy="true")

@app.route('/channels')
def channels():
    selected = request.args.getlist('channel')
    if selected:
        print('selected:', selected)
        pfx = 'proxy' if request.args.get('proxy') else ''
        return redirect('/%s?%s' % (pfx, ','.join(selected)))
    return render_template('channels.html', proxy=is_https())

@app.route('/channels.json')
def channels_json():
    channel_url = 'http://%s' % domain_raw
    if 'http' in domain_raw:
        channel_url = domain_raw
    r = requests.get(channel_url, allow_redirects=True)

    channels = []
    
    s = BeautifulSoup(r.text)
    def parse_link(link):
        cid = None
        name = None
        if link:
            cid = link[0].get('href')
            if cid:
                cid = urlparse(cid)
                if cid:
                    cid = cid.path.replace('/', '')
            name = link[0].text
        
        if cid and name:
            channels.append({"id": cid, "name": name})

    for item in set(s.select('ol li')) | set(s.select('div.grid-item')):
        print('channels_json li item', item)
        link = item.select('a')
        parse_link(link)

    channels.sort(key=lambda x: x['name'])

    print('channels_json', channels)
    return {"channels": channels}

@app.route('/m3u8s/<path:streams>')
def m3u8s_route(streams):
    print('streams:', streams)

    out = {}
    if len(m3u8s) == 0:
        for s in streams.split(','):
            requested_m3u8_streams.labels(domain, s, is_https()).inc()

            if not s in m3u8s:
                _get_m3u8_time = get_m3u8_time.labels(domain, s)
                with _get_m3u8_time.time():
                    fetched_m3u8_streams.labels(domain, s, is_https()).inc()
                    m3u8s[s] = get_m3u8(s)

            out[s] = m3u8s[s]
    
    return out

@app.route('/m3u8/<path:s>')
def m3u8_route(s):
    print('stream:', s)
    requested_m3u8_streams.labels(domain, s, is_https()).inc()

    out = {}

    if not s in m3u8s:
        _get_m3u8_time = get_m3u8_time.labels(domain, s)
        with _get_m3u8_time.time():
            fetched_m3u8_streams.labels(domain, s, is_https()).inc()
            m3u8s[s] = get_m3u8(s)

    out[s] = m3u8s[s]
    
    print('returning:', s)
    return out

def proxy_url_for(stream_id, url):
    u = urljoin(request.base_url, '/proxy_url?stream=%s&url=%s' % (stream_id, url))
    
    if is_https() and u.startswith('http://'):
        u = 'https://' + u[len('http://'):]
    return u

def rewrite_m3u8(raw, url, stream_id):
    out = []
    for line in raw.splitlines():
        if line.startswith('#') or line.startswith('http'):
            out.append(line)
        else:
            rawurl = urljoin(url, line)
            pu = proxy_url_for(stream_id, rawurl)
            allowed_proxy_domains.add(urlparse(rawurl).netloc)
            out.append(pu)
    return '\n'.join(out)

@app.route('/allowed_proxy_domains')
def get_allowed_proxy_domains():
    return {"allowed_proxy_domains": list(allowed_proxy_domains)}

@app.route('/favicon.ico')
def favicon_ico():
    return ''

@app.route('/proxy_url')
def proxy_url_route():
    url = request.query_string.decode()
    if not url or "url=" not in url:
        abort(404, description="no URL")
        return
    stream_id = url.split('&')[0].split('stream=')[1]
    url = url.split('url=', 1)[1]
    proxy_domain = urlparse(url).netloc
    if proxy_domain not in allowed_proxy_domains:
        print("Disallowed proxy domain domain:", proxy_domain, "url:", url)
        invalid_proxy_domains.labels(domain, stream_id, proxy_domain, is_https()).inc()
        abort(403, description="Disallowed proxy domain: %s" % proxy_domain)
        return

    r = requests.get(url, headers={'referer': 'http://%s' % domain})
    ct = r.headers['content-type']
    if ct.lower() == 'application/vnd.apple.mpegurl':
        print('Proxying m3u8 %s' % url)
        proxied_m3u8_streams.labels(domain, stream_id, proxy_domain, is_https()).inc()
        return Response(rewrite_m3u8(r.text, url, stream_id), mimetype=ct)
    print('Proxying raw content %s' % url)
    proxied_m3u8_clips.labels(domain, stream_id, proxy_domain, is_https()).inc()
    return Response(r.content, mimetype=ct)

@app.route('/m3u8_proxy/<path:s>')
def m3u8_proxy_route(s):
    print('stream:', s)

    proxied_m3u8_streams.labels(domain, s, '', is_https()).inc()
    if not s in m3u8s:
        _get_m3u8_time = get_m3u8_time.labels(domain, s)
        with _get_m3u8_time.time():
            m3u8s[s] = get_m3u8(s)

    r = requests.get(m3u8s[s], headers={'referer': 'http://%s' % domain})
    
    print('returning direct m3u8:', s)
    return Response(rewrite_m3u8(r.text, m3u8s[s], s), mimetype=r.headers['content-type'])

@app.route('/expire/<path:s>')
def expire(s):
    count = []
    for t in s.split(','):
        print('expire:', t)
        if t in m3u8s:
            del m3u8s[t]
            print('deleted', t)
            count.append(t)

    if count:
        return 'deleted {}'.format(count)
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
    if firefox_binary:
        opts.binary_location = firefox_binary

    fp = FirefoxProfile()
    fp.set_preference("media.volume_scale", "0.0")

    if domain:
        driver_url = 'https://%s/%s' % (domain, stream)
    else:
        driver_url = 'https://%s' % (stream)
    print("Starting webdriver: %s" % driver_url)

    driver = Firefox(options=opts, firefox_profile=fp)
     
    try:
        print("Installing ublock..")
        check_ublock_xpi()
        driver.install_addon(os.path.join(os.getcwd(), ublock_xpi), temporary=True)
        print("Done installing")
    except Exception as e:
        print(e)

    def click_play_button():
        try:
            play_button = driver.find_element(By.CSS_SELECTOR, ".stream-single-center-message-box > span")
            if play_button:
                WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.CSS_SELECTOR, '.stream-single-center-message-box > span')))
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
                f = driver.execute_script("return typeof(player.options) != 'undefined' && typeof(player.version) == 'undefined' ? player.options.source : ''")
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
    
    def get_bitmovin_url():
        try:
            exists = driver.execute_script("return typeof(player)")
            if exists == "undefined":
                print("undefined bitmovin!")
                return None
            f = None
            for i in range(3):
                f = driver.execute_script("return typeof(player.options) == 'undefined' && typeof(player.version) != 'undefined' ? player.getSource()['hls'] : ''")
                if f != "":
                    break
                time.sleep(1)
            if f:
                print('found m3u8:', f)
                if f.startswith('https:///'):
                    f = f.replace('https:///', 'https://%s/' % domain)
                elif f.startswith('//'):
                    f = 'https:' + f
                return f
        except Exception as e:
            print("exception", e)

        return None
    
    url_attempts = [get_jwplayer_url, get_clappr_url, get_bitmovin_url]

    try:
        driver.get(driver_url)
        print("Page loaded: %s" % driver_url)

        click_play_button()

        for f in url_attempts:
            url = f()
            if url:
                return url

        seq = driver.find_elements(By.TAG_NAME, 'iframe')
        for index in range(len(seq)):
            driver.switch_to.default_content()
            iframe = driver.find_elements(By.TAG_NAME, 'iframe')[index]
            print('processing iframe %d' % index)
            driver.switch_to.frame(iframe)
            try:    

                for f in url_attempts:
                    url = f()
                    if url:
                        return url

            except Exception as e:
                print('exception:', e)
            
            inner_seq = driver.find_elements(By.TAG_NAME, 'iframe')
            for index2 in range(len(inner_seq)):
                driver.switch_to.default_content()
                driver.switch_to.frame(iframe)
                inner_iframe = driver.find_elements(By.TAG_NAME, 'iframe')[index2]
                print('processing inner iframe %d' % index2)
                driver.switch_to.frame(inner_iframe)
                try:    

                    for f in url_attempts:
                        url = f()
                        if url:
                            return url

                except Exception as e:
                    print('exception:', e)
    finally:
        driver.quit()
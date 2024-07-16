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
import cloudscraper
from urllib.parse import urljoin, urlparse, quote

import json
import time
import os, os.path

cs = cloudscraper.create_scraper()

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
if not domain_raw:
    print("No DOMAIN environment variable")
    exit(1)

domain = domain_raw
if domain_raw and 'http' in domain_raw:
    domain = urlparse(domain_raw).netloc
firefox_binary = os.getenv('FIREFOX_BINARY')
proxy_is_https = os.getenv('PROXY_IS_HTTPS')
proxy_default = os.getenv('PROXY_DEFAULT', '') == 'true'
debug_wait = os.getenv('DEBUG_WAIT')

def is_https():
    cf_https = request.headers.get('CF-Visitor') and 'https' in request.headers.get('CF-Visitor')
    return bool(proxy_is_https or cf_https)


ublock_xpi = 'ublock.xpi'
UBLOCK_RELEASES = 'https://github.com/gorhill/uBlock/releases'

def check_ublock_xpi():
    if not os.path.exists(ublock_xpi):
        print("Downloading uBlock extension...")
        r = cs.get(UBLOCK_RELEASES)
        if r.status_code/100 == 2:
            s = BeautifulSoup(r.text)
            for item in s.select('a'):
                link = item.get('href')
                if link.endswith('.firefox.signed.xpi'):
                    print("ublock.xpi link:", link)
                    rx = cs.get(link)
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
    return render_template('channels.html', proxy=is_https() or proxy_default)

last_channels_json = None
last_channels_json_time = None
@app.route('/channels.json')
def channels_json():
    global last_channels_json, last_channels_json_time
    if last_channels_json and time.time() - last_channels_json_time < 120:
        return {"channels": last_channels_json}

    print('uncached channels_json')

    channel_url = 'http://%s' % domain_raw
    if 'http' in domain_raw:
        channel_url = domain_raw
    r = cs.get(channel_url, allow_redirects=True)

    channels = []
    
    s = BeautifulSoup(r.text)
    def parse_link(link):
        cid = None
        name = None
        if link:
            cid = link[0].get('href')
            if cid:
                cid = urlparse(cid)
                if cid and cid.path.startswith('/'):
                    cid = cid.path[1:]
                if '/' in cid:
                    cid = cid.replace('/', '%2F')
            name = link[0].text
        
        if cid and name:
            channels.append({"id": cid, "name": name})

    for item in set(s.select('ol li')) | set(s.select('div.grid-item')) | set(s.select('.grid-items .element')) | set(s.select('.btn.btn-lg')):
        print('channels_json li item', item)
        link = item.select('a')
        parse_link(link)

    if not channels:
        for item in set(s.select('table tbody tr td')):
            print('channels_json li item', item)
            link = item.select('a')
            parse_link(link)

    channels.sort(key=lambda x: x['name'])

    print('channels_json', json.dumps(channels))
    last_channels_json = channels
    last_channels_json_time = time.time()
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
    
    return {k: v.json() if v else None for k, v in out.items()}

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
    
    print('returning for', s, ':', out)
    return {k: v.json() if v else None for k, v in out.items()}

def proxy_url_for(stream_id, url):
    u = urljoin(request.base_url, '/proxy_url?stream=%s&url=%s' % (stream_id, quote(url)))
    
    if is_https() and u.startswith('http://'):
        u = 'https://' + u[len('http://'):]
    return u

def rewrite_m3u8(raw, url, stream_id):
    out = []
    for line in raw.splitlines():
        if line.startswith('#') or not line.startswith('http'):
            out.append(line)
        else:
            rawurl = urljoin(url, line)
            pu = proxy_url_for(stream_id, rawurl)
            allowed_proxy_domains.add(urlparse(rawurl).netloc)
            out.append(pu)
    print('to:', out)
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

    if stream_id not in m3u8s:
        stream_id = stream_id.replace('/', '%2F')
    
    if stream_id not in m3u8s:
        print("Unknown stream_id", stream_id, "m3u8s:", m3u8s)
        abort(403, description="Unknown stream_id: %s" % stream_id)
        return

    url = url.split('url=', 1)[1]
    proxy_domain = urlparse(url).netloc
    if proxy_domain not in allowed_proxy_domains:
        print("Disallowed proxy domain domain:", proxy_domain, "url:", url)
        invalid_proxy_domains.labels(domain, stream_id, proxy_domain, is_https()).inc()
        abort(403, description="Disallowed proxy domain: %s" % proxy_domain)
        return

    referer = m3u8s[stream_id].referer or 'http://%s' % domain
    print('using referer', referer)
    r = cs.get(url, headers={'referer': referer}, allow_redirects=True)
    ct = r.headers['content-type']
    if ct.lower() == 'application/vnd.apple.mpegurl':
        print('Proxying m3u8', url, '>', r.url)
        proxied_m3u8_streams.labels(domain, stream_id, proxy_domain, is_https()).inc()
        return Response(rewrite_m3u8(r.text, r.url, stream_id), mimetype=ct)
    print('Proxying raw content', url, '>', r.url)
    content = r.content
    if r.status_code//100 != 2 or len(content) < 2:
        print('status code:', r.status_code, content)
    proxied_m3u8_clips.labels(domain, stream_id, proxy_domain, is_https()).inc()
    return Response(content, mimetype=ct)

@app.route('/m3u8_proxy/<path:s>')
def m3u8_proxy_route(s):
    print('stream:', s)

    proxied_m3u8_streams.labels(domain, s, '', is_https()).inc()
    if not s in m3u8s:
        _get_m3u8_time = get_m3u8_time.labels(domain, s)
        with _get_m3u8_time.time():
            m3u8s[s] = get_m3u8(s)
    
    if not m3u8s[s]:
        abort(403, "no m3u8 able to be fetched")
        return

    r = cs.get(m3u8s[s].url, headers={'referer': m3u8s[s].referer or 'http://%s' % domain}, allow_redirects=True)
    
    print('returning direct m3u8:', s)
    return Response(rewrite_m3u8(r.text, m3u8s[s].url, s), mimetype=r.headers['content-type'])

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

class M3u8Result:
    def __init__(self, url=None, referer=None):
        r = cs.head(url)
        if r and 'location' in r.headers:
            loc = r.headers['location']
            if len(urlparse(loc).path) > 2:
                url = loc
                print("M3u8Result rewrote url:", url)
        self.url = url
        self.referer = referer
    
    def __str__(self):
        return "M3u8Result(url=%s, referer=%s)" % (self.url, self.referer)
    
    def __repr__(self):
        return self.__str__()
    
    def json(self):
        return {"url": self.url, "referer": self.referer}

currently_open_webdrivers = set()
def get_m3u8(stream):
    if stream in currently_open_webdrivers:
        for i in range(60 * 4):
            if stream not in currently_open_webdrivers:
                time.sleep(0.1)
                print("--got released lock on", stream)
                return m3u8s.get(stream)
            print("--waiting for lock on", stream)
            time.sleep(0.25)
        return None
    currently_open_webdrivers.add(stream)
    print(">>lock>>", stream)
    ret = get_m3u8_nonthreadsafe(stream)
    currently_open_webdrivers.remove(stream)
    print("<<unlock<<", stream)
    return ret

def get_m3u8_nonthreadsafe(stream):
    opts = Options()
    opts.headless = True
    if debug_wait:
        opts.headless = False
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
        play_button_selectors = ["#opalayer", ".stream-single-center-message-box > span", ".jw-icon.jw-icon-display"]
        for selector in play_button_selectors:
            try:
                play_button = driver.find_element(By.CSS_SELECTOR, selector)
                if play_button:
                    print("waiting for play button:", selector)
                    #WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.CSS_SELECTOR, selector)))
                    #play_button.click()
                    driver.execute_script("var elem=arguments[0]; setTimeout(function() {elem.click();}, 100)", play_button)
                    time.sleep(0.2)
                    print("clicked play button:", selector)
                    time.sleep(1)
            except NoSuchElementException:
                print("no play button:", selector)

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

        time.sleep(3)

        click_play_button()

        for f in url_attempts:
            url = f()
            if url:
                return M3u8Result(url, referer = driver_url)

        seq = driver.find_elements(By.TAG_NAME, 'iframe')
        for index in range(len(seq)):
            driver.switch_to.default_content()
            iframe = driver.find_elements(By.TAG_NAME, 'iframe')[index]
            iframe_src = iframe.get_attribute('src')
            print('processing iframe %d: %s' % (index, iframe_src))
            driver.switch_to.frame(iframe)
            try:    

                for f in url_attempts:
                    url = f()
                    if url:
                        return M3u8Result(url, referer = iframe_src)

            except Exception as e:
                print('exception:', e)
            
            inner_seq = driver.find_elements(By.TAG_NAME, 'iframe')
            for index2 in range(len(inner_seq)):
                driver.switch_to.default_content()
                driver.switch_to.frame(iframe)
                inner_iframe = driver.find_elements(By.TAG_NAME, 'iframe')[index2]
                inner_iframe_src = iframe.get_attribute('src')
                print('processing inner iframe %d: %s' % (index2, inner_iframe_src))
                driver.switch_to.frame(inner_iframe)
                try:    

                    for f in url_attempts:
                        url = f()
                        if url:
                            return M3u8Result(url, referer = inner_iframe_src)

                except Exception as e:
                    print('exception:', e)
    finally:
        if debug_wait:
            time.sleep(600)
        driver.quit()
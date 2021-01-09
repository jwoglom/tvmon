#!/usr/bin/env python3
import os
from flask import Flask, render_template

from selenium.webdriver import Firefox
from selenium.webdriver.firefox.options import Options

app = Flask(__name__)

m3u8s = {}

@app.route('/')
def index():
    return render_template('index.html')

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
    for s in m3u8s:
        del m3u8s[s]
        print('deleted', s)
        count += 1

    return 'deleted {}'.format(count)


def get_m3u8(stream):
    opts = Options()
    opts.headless = True
    domain = os.getenv('DOMAIN')

    driver = Firefox(options=opts)

    try:
        driver.get('https://%s/%s/' % (domain, stream))
        seq = driver.find_elements_by_tag_name('iframe')
        for index in range(len(seq)):
            driver.switch_to_default_content()
            iframe = driver.find_elements_by_tag_name('iframe')[index]
            driver.switch_to.frame(iframe)
            try:
                f = driver.execute_script("return jwplayer('player').getPlaylist()[0].file")
                if f:
                    print('found m3u8:', f)
                    if f.startswith('https:///'):
                        f = f.replace('https:///', 'https://%s/' % domain)
                    return f
            except Exception:
                pass
    finally:

        driver.quit()
#-*- coding: utf-8 -*-
#!/usr/bin/env python
"""
        *   @conby C3 Computing Platform code, v3.1
        *
        *   Copyright 2004-2011 @conby C3 development team <support@conby.com>
        *
        *   Licensed under the Apache License, Version 2.0 (the "License");
        *   you may not use this file except in compliance with the License.
        *   You may obtain a copy of the License at
        *
        *       http://www.apache.org/licenses/LICENSE-2.0
        *
        *   Unless required by applicable law or agreed to in writing, software
        *   distributed under the License is distributed on an "AS IS" BASIS,
        *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
        *   See the License for the specific language governing permissions and
        *   limitations under the License.

"""

import os, sys, socket
import string
import urllib, urllib2
import pickle
import base64
import cookielib
import datetime
from random import choice
from optparse import OptionParser
try: import json
except ImportError: import simplejson as json

import c3urlopen

import tornado.ioloop
import tornado.httpserver
import tornado.web
#import tornado.escape
#import tornado.httpclient

try: import fcntl
except ImportError: pass

# import OpenSSL
import geoip2.database

version = '0.010'
C3_SVR_VERSION = 'C3S/2.2'
C3_API_VERSION = 'API/3.5'

GOOGLE_BASE_URL = 'https://googledrive.com/host'
# GOOGLE_BASE_URL = ''
# WEBHDFS_BASE_URL = 'http://comatrix:50070/webhdfs/v1/user/hello'
WEBHDFS_BASE_URL = ''

GEOIP_PATH = 'GeoLite2/GeoLite2-City.mmdb'
DATA_PATH = 'POST'

CA_KEY_PATH = 'CA/private/key.pem'
CA_CERTIFICATE_PATH = 'CA/cacert.pem'

c3_user_agents = [
        'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11) Gecko/20071127 Firefox/2.0.0.11',
        'Opera/9.25 (Windows NT 5.1; U; en)',
        'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
        'Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.5 (like Gecko) (Kubuntu)',
        'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.12) Gecko/20070731 Ubuntu/dapper-security Firefox/1.5.0.12',
        'Lynx/2.8.5rel.1 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/1.2.9'
    ]

class C3RequestHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self._headers['Server'] = C3_SVR_VERSION + ' ' + C3_API_VERSION

class MainHandler(C3RequestHandler):
    
    def save_post_data(self, p_obj, p_key='', file_ext='.post'):
        global DATA_PATH
        res = False
        
        tmp_path = os.path.join(DATA_PATH, datetime.datetime.utcnow().strftime("%Y%m%d") )
        if not os.path.exists(tmp_path):
            os.mkdir(tmp_path)
            
        if not p_key:
            p_key = str(os.getpid())
        tmp_path = os.path.join(tmp_path, p_key + file_ext)

        if not isinstance(p_obj, dict):
            return res

        fp = None
        try:
            fp = open(tmp_path, 'a')
            try:
                if sys.modules.get('fcntl', None):
                    fcntl.flock(fp, fcntl.LOCK_EX|fcntl.LOCK_NB)
                json.dump(p_obj, fp)
                fp.write('\n')
                res = True
            except Exception,e:
                print datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f ") + 'PO096 ' + repr(e)
            finally:
                if sys.modules.get('fcntl', None):
                    fcntl.flock(fp, fcntl.LOCK_UN) 
                fp.close()
                fp = None
        except Exception,e:
            print datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f ") + 'PO099 ' + repr(e)

        return res
        
    def start_c3_response(self):
        self.set_status(200)
        self.set_header("Content-Type", "text/plain; charset=UTF-8")

    def finish_c3_response(self, msg, finish=False):
        self.write(msg)
        self.write('\n')
        self.flush()
        if finish:
            self.finish()

    # @tornado.web.asynchronous
    def get(self):
		# /webhdfs/xxx.json?t=123
        tmp_uri = self.request.uri.split('?')[0]
        if WEBHDFS_BASE_URL and tmp_uri[:9]=='/webhdfs/' and tmp_uri[-5:]=='.json':
            json_name = tmp_uri[9:-5]
            res = None
            url = ''
            try:
                if len(json_name) == 32:
                    url = '%s/json/%s?op=LISTSTATUS' % (WEBHDFS_BASE_URL,json_name)
                else:
                    url = '%s/json/%s.json?op=OPEN' % (WEBHDFS_BASE_URL,json_name)
                res = urllib2.urlopen(url)
            except Exception,e:
                pass
            if res:
                if len(json_name) == 32 and res.code==200:
                    try:
                        json_liststatus = json.loads(res.read())
                        json_liststatus = json_liststatus['FileStatuses']['FileStatus']
                        json_liststatus.sort(key = lambda x:x["pathSuffix"])
                        if json_liststatus[0]['pathSuffix'] == '_SUCCESS':
                            content_getmerge = ''
                            for i in range(len(json_liststatus)-1):
                                url = '%s/json/%s/%s?op=OPEN' % (WEBHDFS_BASE_URL,json_name,json_liststatus[i+1]['pathSuffix'])
                                res = urllib2.urlopen(url)
                                if res and res.code==200:
                                    content_getmerge += res.read()
                                else:
                                    content_getmerge = ''
                                    self.start_c3_response()
                                    self.finish_c3_response("none3")
                                    break
                            self.set_status(200)
                            self.set_header("Content-Type", 'application/json')
                            self.set_header("Content-Length", len(content_getmerge))
                            self.write(content_getmerge)
                            self.flush()
                            self.finish()
                        else:
                            self.start_c3_response()
                            self.finish_c3_response("none2")
                    except Exception,e:
                        self.start_c3_response()
                        self.finish_c3_response("none1")
                else:
                    self.set_status(res.code)
                    # if res.headers.get('Content-Type'):
                    #     self.set_header("Content-Type", res.headers.get('Content-Type'))
                    # else:
                    self.set_header("Content-Type", 'application/json')
                    content_getmerge = res.read()
                    if res.headers.get('Content-Length'):
                        self.set_header("Content-Length", res.headers.get('Content-Length'))
                    else:
                        self.set_header("Content-Length", len(content_getmerge))
                    self.write(content_getmerge)
                    self.flush()
                    self.finish()
            else:
                self.start_c3_response()
                self.finish_c3_response("none")
        # /google/xxx.jpg?t=123 -> https://googledrive.com/host/0BwDPIDViQX1TWTRTXzB2Z3B4Q0U
        elif GOOGLE_BASE_URL and tmp_uri[:8]=='/google/':
            fileid_name = tmp_uri[8:]
            fileid_name = fileid_name.split('.')[0]
            res = None
            url = ''
            try:
                url = '%s/%s' % (GOOGLE_BASE_URL,fileid_name)
                req=urllib2.Request(url)
                req.add_header('User-agent', choice(c3_user_agents))
                res = urllib2.urlopen(req)
            except Exception,e:
                pass
            if res:
                self.set_status(res.code)
                if res.headers.get('Content-Type'):
                    self.set_header("Content-Type", res.headers.get('Content-Type'))
                # else:
                #    self.set_header("Content-Type", 'application/json')
                content_getmerge = res.read()
                if res.headers.get('Content-Length'):
                    self.set_header("Content-Length", res.headers.get('Content-Length'))
                else:
                    self.set_header("Content-Length", len(content_getmerge))
                self.write(content_getmerge)
                self.flush()
                self.finish()
            else:
                self.start_c3_response()
                self.finish_c3_response("none")
        elif tmp_uri[:5]=='/myip':
            req_info = self.request.remote_ip

            self.start_c3_response()
            self.finish_c3_response(req_info)                
        elif tmp_uri[:6]=='/whois':
            global GEOIP_PATH
            req_info = '<html>\n'
            req_info += '<pre>\n'
            req_info += 'host ' + self.request.host + '\n'
            req_info += 'protocol ' + self.request.protocol + '\n'
            req_info += 'version ' + self.request.version + '\n'
            req_info += 'remote_ip ' + self.request.remote_ip + '\n'
            geoip_str = ''
            geoip_response = None
            geoip_reader = None            
            try:
                geoip_reader = geoip2.database.Reader(GEOIP_PATH)
                if geoip_reader:
                    geoip_response = geoip_reader.city(self.request.remote_ip)
                    if geoip_response:
                        if geoip_response.city:
                            if geoip_response.city.name:
                                geoip_str = geoip_response.city.name + ',' 
                        if geoip_response.country:
                            if geoip_response.country.name:
                                geoip_str += geoip_response.country.name
            except:
                pass
            geoip_response = None
            geoip_reader = None
                            
            req_info += 'geoip ' + geoip_str + '\n'

            for k in self.request.headers:
                req_info += k + ' ' + self.request.headers[k] + '\n'
            req_info += '</pre>\n'
            req_info += '</html>\n'
            self.set_status(200)
            self.set_header("Content-Type", "text/html; charset=UTF-8")
            self.finish_c3_response(req_info)
        else:
            self.start_c3_response()
            self.finish_c3_response("API server accepts POST requests only.")

    # @tornado.web.asynchronous
    def post(self):
        self.start_c3_response()
        if not self.get_argument('c3_service_name', None):
            self.finish_c3_response('API name is required', True)
            return

        str_service_name = self.get_argument('c3_service_name', None)

        if str_service_name == 'c3_save_post':
            post_dict = {}
            post_dict['time'] = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f ")
            post_dict['host'] = self.request.host
            post_dict['protocol'] = self.request.protocol
            post_dict['method'] = self.request.method
            post_dict['version'] = self.request.version
            post_dict['uri'] = self.request.uri
            post_dict['remote_ip'] = self.request.remote_ip
            tmp_headers = {}
            for k in self.request.headers:
                tmp_headers[k] = self.request.headers[k]
            post_dict['headers'] = tmp_headers
            tmp_arguments = {}
            for k in self.request.arguments:
                tmp_arguments[k] = self.get_argument(k)          
            post_dict['arguments'] = tmp_arguments
            
            res = self.save_post_data(post_dict)
            self.finish_c3_response('OK' if res else 'NG', True)
            return
 
        if str_service_name == 'c3_urlopen':
            if not self.get_argument('c3_request', None) or not self.get_argument('c3_header', None): 
                self.finish_c3_response('c3_request|c3_header is required', True)
                return

            rpc_result = ''
            # str_rtk = self.get_argument('t')

            try:
                opener=None
                rpc_error = ''
                if len(self.get_argument('c3_proxy'))>5:
                    opener=urllib2.build_opener(urllib2.ProxyHandler({'http': self.get_argument('c3_proxy')}))
                else:
                    opener=urllib2.build_opener()

                #opener.addheaders.append(('Connection','keep-alive'))
                ds_addheader = None
                ds_addheader=pickle.loads(base64.decodestring(self.get_argument('c3_header')))
                opener.addheaders=[('User-agent',ds_addheader.get('User-agent'))]
                for k in ds_addheader:
                    if k!='User-agent':
                        opener.addheaders.append((k,ds_addheader.get(k)))
    
                urllib2.install_opener(opener)
                req = None
                cj=cookielib.CookieJar()
                # print self.get_argument('c3_request')
                #req=pickle.loads(base64.decodestring(self.get_argument('c3_request')))
                c3_req=pickle.loads(base64.decodestring(self.get_argument('c3_request')))

                if len(c3_req['body'])==0:
                    req=urllib2.Request(c3_req['url'])
                else:
                    req=urllib2.Request(c3_req['url'],c3_req['body'])
                for tmp_cookie in c3_req['cookies']:
                    cj.set_cookie_if_ok(tmp_cookie, req)
                cj.add_cookie_header(req)

                #print req
                long_timeout = 60
                if self.get_argument('c3_timeout'):
                    try:
                        long_timeout = long(self.get_argument('c3_timeout'))
                    except Exception,e:
                        pass
                res=urllib2.urlopen(req, timeout = long_timeout)
                cookies = None
                my_urlopen_obj = None
                if res:
                    #cj=cookielib.CookieJar()
                    cj.extract_cookies(res, req)
                    cookies = cj.make_cookies(res, req)

                    my_urlopen_obj = c3urlopen.C3UrlopenObject()
                    my_urlopen_obj.c3_clone(res)
                    res = my_urlopen_obj
                rpc_result = json.dumps({'error': '','cookies': base64.encodestring(pickle.dumps(cookies)), 'response': base64.encodestring(pickle.dumps(res))})
            #except apiproxy_errors.OverQuotaError,e:
            #    rpc_error = "#OverQuotaError: " + repr(e)
            #    rpc_result = json.dumps({'error': rpc_error,'cookies': base64.encodestring(pickle.dumps([])), 'response': base64.encodestring(pickle.dumps(None))})
            except urllib2.HTTPError,e:
                rpc_error = "#HTTPError: " + str(e.code)
                rpc_result = json.dumps({'error': rpc_error,'cookies': base64.encodestring(pickle.dumps([])), 'response': base64.encodestring(pickle.dumps(None))})
            except urllib2.URLError, e:
                if isinstance(e.reason, socket.timeout):
                    rpc_error = "#URLError: timeout("+ repr(self.get_argument('c3_timeout'))+") " + str(e.args)
                else:
                    rpc_error = "#URLError: " + str(e.args)
                rpc_result = json.dumps({'error': rpc_error,'cookies': base64.encodestring(pickle.dumps([])), 'response': base64.encodestring(pickle.dumps(None))})
            except Exception,e:
                rpc_error = "#Exception: " + repr(e)
                rpc_result = json.dumps({'error': rpc_error,'cookies': base64.encodestring(pickle.dumps([])), 'response': base64.encodestring(pickle.dumps(None))})
            # print rpc_result

            self.finish_c3_response(rpc_result, True)
            return

 
        self.finish_c3_response('No such API.', True)

    def on_response(self, response):
        #self.set_header("Content-Type", "text/plain")
        #if response.error: 
        #    #raise tornado.web.HTTPError(500)
        #else:
        self.finish_c3_response(response.body, True)

    def options(self):
        self.start_c3_response()
        if self._headers.get('origin'):
            self.set_header('Access-Control-Allow-Origin',  self._headers['origin'])             
        else:
            self.set_header('Access-Control-Allow-Origin', '*')   
        self.set_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.set_header("Access-Control-Allow-Headers", "X-Requested-With")
        self.flush()

def main():

    parser = OptionParser()
    parser.add_option('-n', '--process', dest='process',
                        help='process number to serve as (default: %default)',
                        default='2')
    parser.add_option('-p', '--port', dest='port',
                        help='port to binding HTTP server (default: %default)',
                        default='8085')
    parser.add_option('-t', '--http', dest='http',
                        help='port to binding HTTP server (default: %default)',
                        default='')                        

    options, args = parser.parse_args()
    c3path = os.path.normpath(os.path.join(os.getcwd(),os.path.dirname(__file__)))

    application = tornado.web.Application([(r".*", MainHandler),])
    sockets = None
    sockets_ssl = None
    ioloop = None

    try:
        if options.http:
            sockets = tornado.netutil.bind_sockets(string.atoi(options.http))
        sockets_ssl = tornado.netutil.bind_sockets(string.atoi(options.port))
        print datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"), 'Binding HTTP/HTTPS', options.http, options.port
    except socket.error as e:
        print datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"), 'HTTP/HTTPS', options.http, options.port, repr(e)

    if sockets_ssl:
        try:
            server = None
            tornado.process.fork_processes(string.atoi(options.process))

            # X-Real-Ip/X-Forwarded-For and X-Scheme/X-Forwarded-Proto
            if sockets:
                server = tornado.httpserver.HTTPServer(application, xheaders=True)
                if server:
                    server.add_sockets(sockets)
            server_ssl = tornado.httpserver.HTTPServer(application, xheaders=True, ssl_options={"certfile": os.path.join(c3path, CA_CERTIFICATE_PATH),"keyfile": os.path.join(c3path, CA_KEY_PATH)})
            global GEOIP_PATH, DATA_PATH
            GEOIP_PATH = os.path.join(c3path, GEOIP_PATH)
            DATA_PATH = os.path.join(c3path, DATA_PATH)
            if server_ssl:
                server_ssl.add_sockets(sockets_ssl)
                ioloop = tornado.ioloop.IOLoop.instance()
                # ioloop.add_timeout(time.time() + 0.1, application.mq.connect)
                ioloop.start()
        except KeyboardInterrupt, e:
            print datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"), 'WP200 ', repr(e)

    print datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"), 'Bye C3 Web Proxy'

if __name__ == '__main__':
    main()


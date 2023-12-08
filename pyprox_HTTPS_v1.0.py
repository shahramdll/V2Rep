#!/usr/bin/env python3

import dns.message   #  --> pip install dnspython
import dns.rdatatype
import requests      #  --> pip install requests
from pathlib import Path
import os
import base64
import socket
import threading
import time
import random


listen_PORT = 4500    # pyprox listening to 127.0.0.1:listen_PORT

num_fragment = 150  # total number of chunks that ClientHello devided into (chunks with random size)
fragment_sleep = 0.001  # sleep between each fragment to make GFW-cache full so it forget previous chunks. LOL.

log_every_N_sec = 10
#DNS_url = 'https://cloudflare-dns.com/dns-query?dns='      # not working in iran , ip blocked
#DNS_url = 'https://dns.google/dns-query?dns='              # not working in iran , ip blocked
#DNS_url = 'https://doh.opendns.com/dns-query?dns='           # not working in iran , ip blocked
#DNS_url = 'https://secure.avastdns.com/dns-query?dns='      # not working in iran , ip blocked
#DNS_url = 'https://doh.libredns.gr/dns-query?dns='          # not working in iran , ip blocked
#DNS_url = 'https://dns.electrotm.org/dns-query?dns='
#DNS_url = 'https://doh.dnscrypt.uk/dns-query?dns='
#DNS_url = 'https://v.dnscrypt.uk/dns-query?dns='
DNS_url = 'https://doh.umbrella.com/dns-query?dns='



offline_DNS = {

################## DNS over HTTPS IP Address (leave it intact , it must Exist) ######################
'cloudflare-dns.com':'1.1.1.1',    # not working in iran , ip blocked
'dns.google':'8.8.8.8',    # not working in iran , ip blocked
'doh.opendns.com':'208.67.222.222',    # not working in iran , ip blocked
'secure.avastdns.com':'185.185.133.66',  # not working in iran , ip blocked
'doh.libredns.gr':'116.202.176.26',        # not working in iran , ip blocked    
'dns.electrotm.org':'78.157.42.100',
'doh.dnscrypt.uk':'165.227.233.200',
'v.dnscrypt.uk':'136.244.65.20',
'doh.umbrella.com':'146.112.41.5',
##########################################################################

'youtube.com':'google.com'
'doh.umbrella.com':'146.112.41.5'
'instagram.com':'163.70.128.63'
'graph.instagram.com':'163.70.128.63'
'graphql.instagram.com':'163.70.128.63'
'api.instagram.com':'163.70.128.63'
'blog.instagram.com':'163.70.128.13'
'about.instagram.com':'163.70.128.13'
'platform.instagram.com':'163.70.128.63'
'privacy.instagram.com':'163.70.128.63'
'parents.instagram.com':'163.70.128.63'
'safety.instagram.com':'163.70.128.63'
'wellbeing.instagram.com':'163.70.128.63'
'upload.instagram.com':'163.70.128.63'
'upload-ec2.instagram.com':'163.70.128.63'
'white.instagram.com':'163.70.128.63'
'black.instagram.com':'163.70.128.63'
'survey.instagram.com':'163.70.128.63'
'mail.instagram.com':'163.70.128.63'
'maps.instagram.com':'163.70.128.63'
'i.instagram.com':'163.70.128.63'
'l.instagram.com':'163.70.128.63'
'admin.instagram.com':'163.70.128.63'
'i-fallback.instagram.com':'163.70.128.63'
'gateway.instagram.com':'163.70.128.63'
'static.cdninstagram.com':'163.70.128.63'
'scontent.cdninstagram.com':'163.70.128.63'
'business.instagram.com':'163.70.128.63'
'applink.instagram.com':'163.70.128.63'
'autodiscover.instagram.com':'163.70.128.63'
'b.i.instagram.com':'163.70.128.63'
'b.secure.instagram.com':'163.70.128.63'
'badges.instagram.com':'163.70.128.63'
'business.intern.instagram.com':'163.70.128.63'
'businessphoneservicea5.latest.instagram.com':'163.70.128.63'
'ceheindependence.latest.instagram.com':'163.70.128.63'
'climatecommunication.latest.instagram.com':'163.70.128.63'
'coloredlogs.beta.latest.instagram.com':'163.70.128.63'
'community.instagram.com':'163.70.128.63'
'display.latest.instagram.com':'163.70.128.63'
'dyi.www.instagram.com':'163.70.128.63'
'edge-chat.instagram.com':'163.70.128.63'
'employee.instagram.com':'163.70.128.63'
'eulauretta.instagram.com':'163.70.128.63'
'geo.instagram.com':'163.70.128.63'
'grammys.instagram.com':'163.70.128.63'
'guia-lima.latest.instagram.com':'163.70.128.63'
'help.hyperlase.beta.latest.instagram.com':'163.70.128.63'
'help.instagram.com':'163.70.128.63'
'help.latest.instagram.com':'163.70.128.63'
'hyperlapse.instagram.com':'163.70.128.63'
'live-dev.instagram.com':'163.70.128.63'
'live-upload.instagram.com':'163.70.128.63'
'live-upload-staging.instagram.com':'163.70.128.63'
'live-vp-dev.instagram.com':'163.70.128.63'
'live-vp-upload.instagram.com':'163.70.128.63'
'logger.instagram.com':'163.70.128.63'
'lookaside.instagram.com':'163.70.128.63'
'm.help.instagram.com':'163.70.128.63'
'nsecure.latest.instagram.com':'163.70.128.63'
'secure.latest.instagram.com':'163.70.128.63'
'shortwave.instagram.com':'163.70.128.63'
'streaming-graph.instagram.com':'163.70.128.63'
'telegraph-ash.instagram.com':'163.70.128.63'
'threatmap.latest.instagram.com':'163.70.128.63'
'tpompspc.latest.instagram.com':'163.70.128.63'
'www.latest.instagram.com':'163.70.128.63'
'instagram-p42-shv-03-cdg4.fbcdn.net':'163.70.128.63'
'scontent-cdt1-1.cdninstagram.com':'163.70.128.63'
'scontent-mct1-1.cdninstagram.com':'163.70.128.63'
'scontent-ist1-1.cdninstagram.com':'163.70.128.63'
'scontent-prg1-1.cdninstagram.com':'163.70.128.63'
'scontent-arn2-1.cdninstagram.com':'163.70.128.63'
'scontent-frx5-1.cdninstagram.com':'163.70.128.63'
'scontent-cdg4-1.cdninstagram.com':'163.70.128.63'
'scontent-cdg4-2.cdninstagram.com':'163.70.128.63'
'scontent-cdg4-3.cdninstagram.com':'163.70.128.63'
'edge-mqtt.facebook.com':'163.70.128.4'
'edge-star-mini-shv-03-cdg4.facebook.com':'163.70.128.35'
'edge-dgw-shv-03-cdg4.facebook.com':'163.70.128.63'
'facebook.com':'163.70.128.35'
'graph.facebook.com':'163.70.128.35'
'messenger.com':'163.70.128.35'
'static.xx.fbcdn.net':'163.70.128.35'
'scontent.xx.fbcdn.net':'163.70.128.23'
'video-mct1-1.xx.fbcdn.net':'163.70.128.23'
'scontent-mct1-1.xx.fbcdn.net':'163.70.128.23'
'developers.facebook.com':'31.13.84.8'
'connect.facebook.net':'31.13.84.51'
'meta.com':'163.70.128.13'
'whatsapp.com':'163.70.128.60'
'web.whatsapp.com':'163.70.128.60'
'api.whatsapp.com':'163.70.128.60'
'account.whatsapp.com':'163.70.128.60'
'autodiscover.whatsapp.com':'40.100.146.184'
'whatsapp.net':'163.70.128.60'
'static.whatsapp.net':'163.70.128.60'
'scontent.whatsapp.net':'163.70.128.60'
'chat.cdn.whatsapp.net':'163.70.128.61'
'dit.whatsapp.net':'163.70.128.60'
'pps.whatsapp.net':'163.70.128.60'
'g-fallback.whatsapp.net':'163.70.128.61'
'g.whatsapp.net':'163.70.128.61'
'graph.whatsapp.net':'163.70.128.60'
'wa.me':'163.70.128.60'
'privatestats.whatsapp.net':'163.70.128.60'
'test-web.whatsapp.com':'163.70.128.60'
'translate.whatsapp.com':'163.70.128.60'
'v.whatsapp.com':'163.70.128.60'
'v.whatsapp.net':'163.70.128.60'
'whatsapp.fbsbx.com':'163.70.128.60'
'fna-whatsapp-shv-01-fsea1.fbcdn.net':'163.70.128.60'
'fna-whatsapp-shv-01-fsjo10.fbcdn.net':'163.70.128.60'
'fna-whatsapp-shv-02-fixc1.fbcdn.net':'163.70.128.60'
'fna-whatsapp-shv-02-fmaa1.fbcdn.net':'163.70.128.60'
'fna-whatsapp-shv-03-fmaa1.fbcdn.net':'163.70.128.60'
'fna-whatsapp-shv-04-fmaa1.fbcdn.net':'163.70.128.60'
'media-cdt1-1.cdn.whatsapp.net':'163.70.128.60'
'media-mct1-1.cdn.whatsapp.net':'163.70.128.60'
'media-ist1-1.cdn.whatsapp.net':'163.70.128.60'
'media-prg1-1.cdn.whatsapp.net':'163.70.128.60'
'media-arn2-1.cdn.whatsapp.net':'163.70.128.60'
'media-frx5-1.cdn.whatsapp.net':'163.70.128.60'
'media-cdg4-1.cdn.whatsapp.net':'163.70.128.60'
'media-cdg4-2.cdn.whatsapp.net':'163.70.128.60'
'media-cdg4-3.cdn.whatsapp.net':'163.70.128.60'
'media.fabj2-1.fna.whatsapp.net':'163.70.128.60'
'media.fbel3-1.fna.whatsapp.net':'163.70.128.60'
'media.fcgh5-1.fna.whatsapp.net':'163.70.128.60'
'media.fcgk9-1.fna.whatsapp.net':'163.70.128.60'
'media.fdel11-1.fna.whatsapp.net':'163.70.128.60'
'media.fdel3-1.fna.whatsapp.net':'163.70.128.60'
'media.feoh3-1.fna.whatsapp.net':'163.70.128.60'
'media.fevn1-1.fna.whatsapp.net':'163.70.128.60'
'media.ffjr1-1.fna.whatsapp.net':'163.70.128.60'
'media.ffjr1-3.fna.whatsapp.net':'163.70.128.60'
'media.fgye1-1.fna.whatsapp.net':'163.70.128.60'
'media.flos2-1.fna.whatsapp.net':'163.70.128.60'
'media.fmnl10-1.fna.whatsapp.net':'163.70.128.60'
'media.fplu6-1.fna.whatsapp.net':'163.70.128.60'
'media.fqls2-1.fna.whatsapp.net':'163.70.128.60'
'media.frec2-1.fna.whatsapp.net':'163.70.128.60'
'media.frix1-1.fna.whatsapp.net':'163.70.128.60'
'media.frix4-1.fna.whatsapp.net':'163.70.128.60'
'media.fskg1-1.fna.whatsapp.net':'163.70.128.60'
'media.fssa13-1.fna.whatsapp.net':'163.70.128.60'
'media.fsyq1-1.fna.whatsapp.net':'163.70.128.60'
'media.ftpe4-1.fna.whatsapp.net':'163.70.128.60'
'media.fykz1-1.fna.whatsapp.net':'163.70.128.60'
'media.fyxd2-1.fna.whatsapp.net':'163.70.128.60'
'media-ber1-1.cdn.whatsapp.net':'163.70.128.60'
'media-bru2-1.cdn.whatsapp.net':'163.70.128.60'
'media-dfw5-1.cdn.whatsapp.net':'163.70.128.60'
'media-iad3-1.cdn.whatsapp.net':'163.70.128.60'
'media-lax3-1.cdn.whatsapp.net':'163.70.128.60'
'media-lax3-2.cdn.whatsapp.net':'163.70.128.60'
'media-lga3-1.cdn.whatsapp.net':'163.70.128.60'
'media-mad1-1.cdn.whatsapp.net':'163.70.128.60'
'media-mia3-1.cdn.whatsapp.net':'163.70.128.60'
'media-mxp1-1.cdn.whatsapp.net':'163.70.128.60'
'media-otp1-1.cdn.whatsapp.net':'163.70.128.60'
'media-sea1-1.cdn.whatsapp.net':'163.70.128.60'
'media-sin6-1.cdn.whatsapp.net':'163.70.128.60'
'media-sjc3-1.cdn.whatsapp.net':'163.70.128.60'
'media-sof1-1.cdn.whatsapp.net':'163.70.128.60'
'media-vie1-1.cdn.whatsapp.net':'163.70.128.60'
'media-waw1-1.cdn.whatsapp.net':'163.70.128.60'
'whatsapp-cdn-shv-01-arn2.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-atl3.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-bog1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-bom1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-cdg4.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-cdg4-1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-cdg4-2.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-cdg4-3.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-02-cdg4.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-02-cdg4-1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-02-cdg4-2.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-02-cdg4-3.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-dfw5.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-gru2.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-iad3.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-jnb1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-lax3.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-mad1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-mrs2.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-mxp1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-nrt1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-prg1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-qro1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-sea1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-sin6.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-sjc3.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-sof1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-tpe1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-vie1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-waw1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-01-yyz1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-02-bom1.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-02-dfw5.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-02-gru2.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-02-lax3.fbcdn.net':'163.70.128.60'
'whatsapp-cdn-shv-02-sin6.fbcdn.net':'163.70.128.60'
'whatsapp-chatd-edge-shv-01-atl3.facebook.com':'163.70.128.60'
'whatsapp-chatd-edge-shv-01-bru2.facebook.com':'163.70.128.60'
'whatsapp-chatd-edge-shv-01-mad1.facebook.com':'163.70.128.60'
'whatsapp-chatd-edge-shv-01-mxp1.facebook.com':'163.70.128.60'
'whatsapp-chatd-edge-shv-01-sea1.facebook.com':'163.70.128.60'
'whatsapp-chatd-edge-shv-01-syd2.facebook.com':'163.70.128.60'
'whatsapp-chatd-edge-shv-02-atl3.facebook.com':'163.70.128.60'
'whatsapp-chatd-edge-shv-02-bru2.facebook.com':'163.70.128.60'
'whatsapp-chatd-edge-shv-02-mad1.facebook.com':'163.70.128.60'
'whatsapp-chatd-edge-shv-02-mxp1.facebook.com':'163.70.128.60'
'whatsapp-chatd-edge-shv-02-sea1.facebook.com':'163.70.128.60'
'whatsapp-chatd-edge-shv-02-syd2.facebook.com':'163.70.128.60'
'twitter.com':'104.244.42.1'
'x.com':'188.114.98.229'
'api.twitter.com':'104.244.42.66'
'api2.twitter.com':'199.59.149.200'
'graphql.twitter.com':'104.244.42.67'
'help.twitter.com':'104.244.42.72'
'platform.twitter.com':'93.184.220.66'
'abs.twimg.com':'151.101.244.159'
'abs-0.twimg.com':'104.244.43.131',
'pbs.twimg.com':'93.184.220.70'
'video.twimg.com':'192.229.220.133',
'appspot.com':'142.250.179.142',


}





# ignore description below , its for old code , just leave it intact.
my_socket_timeout = 21 # default for google is ~21 sec , recommend 60 sec unless you have low ram and need close soon
first_time_sleep = 0.1 # speed control , avoid server crash if huge number of users flooding
accept_time_sleep = 0.01 # avoid server crash on flooding request -> max 100 sockets per second


DNS_cache = {}      # resolved domains
IP_DL_traffic = {}  # download usage for each ip
IP_UL_traffic = {}  # upload usage for each ip


class DNS_over_Fragment:
    def __init__(self):
        self.url = DNS_url
        self.req = requests.session()              
        self.fragment_proxy = {
        'https': 'http://127.0.0.1:'+str(listen_PORT)
        }
        


    def query(self,server_name):

        offline_ip = offline_DNS.get(server_name,None)
        if(offline_ip!=None):
            print('offline DNS -->',server_name,offline_ip)
            return offline_ip
        
        cache_ip = DNS_cache.get(server_name,None)
        if(cache_ip!=None):
            print('cached DNS -->',server_name,cache_ip)
            return cache_ip

        quary_params = {
            'name': server_name,
            'type': 'A',
            'ct': 'application/dns-message',
            }
        

        print(f'online DNS Query',server_name)        
        try:
            query_message = dns.message.make_query(server_name,'A')
            query_wire = query_message.to_wire()
            query_base64 = base64.urlsafe_b64encode(query_wire).decode('utf-8')
            query_base64 = query_base64.replace('=','')    # remove base64 padding to append in url            

            query_url = self.url + query_base64
            ans = self.req.get( query_url , params=quary_params , headers={'accept': 'application/dns-message'} , proxies=self.fragment_proxy)
            
            # Parse the response as a DNS packet
            if ans.status_code == 200 and ans.headers.get('content-type') == 'application/dns-message':
                answer_msg = dns.message.from_wire(ans.content)

                resolved_ip = None
                for x in answer_msg.answer:
                    if (x.rdtype == dns.rdatatype.A):
                        resolved_ip = x[0].address    # pick first ip in DNS answer
                        DNS_cache[server_name] = resolved_ip                        
                        print("################# DNS Cache is : ####################")
                        print(DNS_cache)         # print DNS cache , it usefull to track all resolved IPs , to be used later.
                        print("#####################################################")
                        break
                
                print(f'online DNS --> Resolved {server_name} to {resolved_ip}')                
                return resolved_ip
            else:
                print(f'Error: {ans.status_code} {ans.reason}')
        except Exception as e:
            print(repr(e))
        








class ThreadedServer(object):
    def __init__(self, host, port):
        self.DoH = DNS_over_Fragment()
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(128)  # up to 128 concurrent unaccepted socket queued , the more is refused untill accepting those.
                        
        while True:
            client_sock , client_addr = self.sock.accept()                    
            client_sock.settimeout(my_socket_timeout)
                        
            time.sleep(accept_time_sleep)   # avoid server crash on flooding request
            thread_up = threading.Thread(target = self.my_upstream , args =(client_sock,) )
            thread_up.daemon = True   #avoid memory leak by telling os its belong to main program , its not a separate program , so gc collect it when thread finish
            thread_up.start()
    


    def handle_client_request(self,client_socket):
        # Receive the CONNECT request from the client
        data = client_socket.recv(16384)
        

        if(data[:7]==b'CONNECT'):            
            server_name , server_port = self.extract_servername_and_port(data)            
        elif( (data[:3]==b'GET') or (data[:4]==b'POST')):            
            q_line = str(data).split('\r\n')
            q_url = q_line[0].split()[1]
            q_url = q_url.replace('http://','https://')   
            print('redirect http to HTTPS',q_url)          
            response_data = 'HTTP/1.1 302 Found\r\nLocation: '+q_url+'\r\nProxy-agent: MyProxy/1.0\r\n\r\n'            
            client_socket.sendall(response_data.encode())
            client_socket.close()            
            return None
        else:
            print('Unknown Method',str(data[:10]))            
            response_data = b'HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n'
            client_socket.sendall(response_data)
            client_socket.close()            
            return None

        
        print(server_name,'-->',server_port)

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(my_socket_timeout)
            server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)   #force localhost kernel to send TCP packet immediately (idea: @free_the_internet)

            server_IP = self.DoH.query(server_name)
            server_socket.connect((server_IP, server_port))
            # Send HTTP 200 OK
            response_data = b'HTTP/1.1 200 Connection established\r\nProxy-agent: MyProxy/1.0\r\n\r\n'            
            client_socket.sendall(response_data)
            return server_socket
        except Exception as e:
            print(repr(e))
            # Send HTTP ERR 502
            response_data = b'HTTP/1.1 502 Bad Gateway\r\nProxy-agent: MyProxy/1.0\r\n\r\n'
            client_socket.sendall(response_data)
            client_socket.close()
            server_socket.close()
            return None







    def my_upstream(self, client_sock):
        first_flag = True
        backend_sock = self.handle_client_request(client_sock)

        if(backend_sock==None):
            client_sock.close()
            return False
        
        this_ip = backend_sock.getpeername()[0]
        if(this_ip not in IP_UL_traffic):
            IP_UL_traffic[this_ip] = 0
        
        
        while True:
            try:
                if( first_flag == True ):                        
                    first_flag = False

                    time.sleep(first_time_sleep)   # speed control + waiting for packet to fully recieve
                    data = client_sock.recv(16384)
                    #print('len data -> ',str(len(data)))                
                    #print('user talk :')

                    if data:                                                                                            
                        thread_down = threading.Thread(target = self.my_downstream , args = (backend_sock , client_sock) )
                        thread_down.daemon = True
                        thread_down.start()
                        # backend_sock.sendall(data)    
                        send_data_in_fragment(data,backend_sock)
                        IP_UL_traffic[this_ip] = IP_UL_traffic[this_ip] + len(data)

                    else:                   
                        raise Exception('cli syn close')

                else:
                    data = client_sock.recv(16384)
                    if data:
                        backend_sock.sendall(data)  
                        IP_UL_traffic[this_ip] = IP_UL_traffic[this_ip] + len(data)                      
                    else:
                        raise Exception('cli pipe close')
                    
            except Exception as e:
                #print('upstream : '+ repr(e) )
                time.sleep(2) # wait two second for another thread to flush
                client_sock.close()
                backend_sock.close()
                return False



            
    def my_downstream(self, backend_sock , client_sock):
        this_ip = backend_sock.getpeername()[0]
        if(this_ip not in IP_DL_traffic):
            IP_DL_traffic[this_ip] = 0


        first_flag = True
        while True:
            try:
                if( first_flag == True ):
                    first_flag = False            
                    data = backend_sock.recv(16384)
                    if data:
                        client_sock.sendall(data)
                        IP_DL_traffic[this_ip] = IP_DL_traffic[this_ip] + len(data)
                    else:
                        raise Exception('backend pipe close at first')
                    
                else:
                    data = backend_sock.recv(16384)
                    if data:
                        client_sock.sendall(data)
                        IP_DL_traffic[this_ip] = IP_DL_traffic[this_ip] + len(data)
                    else:
                        raise Exception('backend pipe close')
            
            except Exception as e:
                #print('downstream '+backend_name +' : '+ repr(e)) 
                time.sleep(2) # wait two second for another thread to flush
                backend_sock.close()
                client_sock.close()
                return False



    def extract_servername_and_port(self,data):        
        host_and_port = str(data).split()[1]
        host,port = host_and_port.split(':')
        return (host,int(port)) 



def merge_all_dicts():
    full_DNS = {**DNS_cache, **offline_DNS}  # merge two dict , need python 3.5 or up
    inv_DNS = { v:k for k, v in full_DNS.items()}  # inverse mapping to look for domain given ip
    stats = {}
    for ip in IP_DL_traffic:  
        up = round(IP_UL_traffic[ip]/(1024.0),3)
        down = round(IP_DL_traffic[ip]/(1024.0),3)
        host = inv_DNS.get(ip,'?')
        if((up>down) and (down<1.0)):  # download below 1KB
            maybe_filter = 'maybe'
        else:
            maybe_filter = '-------'

        su = f'UL={up} KB:'
        sd = f'DL={down} KB:'        
        sf = f'filtered={maybe_filter}:'
        sh = f'Host={host}:'
        stats[ip] = ':'+su+sd+sf+sh
    return stats



# only run in separate thread
def log_writer():
    file_name = 'DNS_IP_traffic_info.txt'
    BASE_DIR = Path(__file__).resolve().parent
    log_file_path = os.path.join(BASE_DIR,file_name)
    
    with open(log_file_path, "w") as f:
        while True:
            time.sleep(log_every_N_sec)
            all_stats_info = merge_all_dicts()           
            f.seek(0)
            f.write('########### new DNS resolved : ##############\n')
            f.write(str(DNS_cache).replace(',',',\n'))
            f.write('\n#############################################\n')
            f.write('\n########### ALL INFO : ######################\n')
            f.write(str(all_stats_info).replace('\'','').replace(',','\n').replace(':','\t'))
            f.write('\n#############################################\n')
            f.flush()
            f.truncate()
            print("info file writed to",f.name )



def start_log_writer():
    thread_log = threading.Thread(target = log_writer , args = () )
    thread_log.daemon = True
    thread_log.start()





def send_data_in_fragment(data , sock):
    L_data = len(data)
    indices = random.sample(range(1,L_data-1), num_fragment-1)
    indices.sort()
    # print('indices=',indices)

    i_pre=0
    for i in indices:
        fragment_data = data[i_pre:i]
        i_pre=i
        # print('send ',len(fragment_data),' bytes')                        
        
        # sock.send(fragment_data)
        sock.sendall(fragment_data)
        
        time.sleep(fragment_sleep)
    
    fragment_data = data[i_pre:L_data]
    sock.sendall(fragment_data)
    print('----------finish------------')




if (__name__ == "__main__"):
    start_log_writer()
    print ("Now listening at: 127.0.0.1:"+str(listen_PORT))
    ThreadedServer('',listen_PORT).listen()



    
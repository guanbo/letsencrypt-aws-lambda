#!/usr/bin/env python

import sys
import time
import base64
import hashlib
import hmac
import json
try:
    import urllib.request as urlrequest
    import urllib.error as urlerror
    from urllib.parse import urlencode, quote
except ImportError:
    import urllib as urlrequest
    import urllib2 as urlerror
    from urllib import urlencode, quote


class AliyunDns:
    __endpoint = 'http://alidns.aliyuncs.com'
    __letsencryptSubDomain = '_acme-challenge'
    __appid = ''
    __appsecret = ''

    def __init__(self, appid, appsecret):
        self.__appid = appid
        self.__appsecret = appsecret

    def __getSignatureNonce(self):
        return int(round(time.time() * 1000))

    def __percentEncode(self, str):
        res = quote(str.encode('utf8'), '')
        res = res.replace('+', '%20')
        res = res.replace('\'', '%27')
        res = res.replace('\"', '%22')
        res = res.replace('*', '%2A')
        res = res.replace('%7E', '~')

        return res

    def __signature(self, params):
        sortedParams = sorted(params.items(), key=lambda params: params[0])

        query = ''
        for (k, v) in sortedParams:
            query += '&' + \
                self.__percentEncode(k) + '=' + self.__percentEncode(str(v))

        stringToSign = 'GET&%2F&' + self.__percentEncode(query[1:])
        key = self.__appsecret + "&"
        h = hmac.new(key.encode(), stringToSign.encode(), hashlib.sha1)
        signature = base64.encodestring(h.digest()).strip()

        return signature

    def __request(self, params):
        commonParams = {
            'Format': 'JSON',
            'Version': '2015-01-09',
            'SignatureMethod': 'HMAC-SHA1',
            'SignatureNonce': self.__getSignatureNonce(),
            'SignatureVersion': '1.0',
            'AccessKeyId': self.__appid,
            'Timestamp':  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        # print(commonParams)

        # merge all params
        finalParams = commonParams.copy()
        finalParams.update(params)

        # signature
        finalParams['Signature'] = self.__signature(finalParams)

        # get final url
        url = '%s/?%s' % (self.__endpoint, urlencode(finalParams))
        # print(url)

        try:
            f = urlrequest.urlopen(url)
            response = f.read()
            # print(response)
            return response
        except urlerror.HTTPError as e:
            print(e.read().strip())
            raise SystemExit(e)

    def getDomainRecords(self, domain):
        params = {
            'Action': 'DescribeDomains',
            'KeyWord': domain
        }
        return self.__request(params)

    def addDomainRecord(self, domain, rr, value):
        params = {
            'Action': 'AddDomainRecord',
            'DomainName': domain,
            'RR': rr,
            'Type': 'TXT',
            'Value': value
        }
        self.__request(params)

    def deleteSubDomainRecord(self, domain, rr):
        params = {
            'Action': 'DeleteSubDomainRecords',
            'DomainName': domain,
            'RR': rr,
            'Type': 'TXT'
        }
        self.__request(params)

    def addLetsencryptDomainRecord(self, domain, value):
        domain, subdomain = self.getDomainPair(domain)
        self.addDomainRecord(domain, subdomain, value)

    def deleteLetsencryptDomainRecord(self, domain):
        domain, subdomain = self.getDomainPair(domain)
        self.deleteSubDomainRecord(domain, subdomain)

    def toString(self):
        print('AliyunDns[appid='+self.__appid +
              ', appsecret='+self.__appsecret+']')

    def getDomainPair(self, domain):
        subdomain = '.'.join([self.__letsencryptSubDomain] + domain.split('.')[:-2])
        domain = '.'.join(domain.split('.')[-2:])
        result = self.getDomainRecords(domain)
        domain = json.loads(result)['Domains']['Domain'][0]['DomainName']
        return domain, subdomain
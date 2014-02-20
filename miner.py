#!/usr/bin/python
#
# Momentum getwork miner by reorder, 2014
#
# Derived from jgarzik's pyminer, original copyright follows
# 
# Copyright 2011 Jeff Garzik
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
#
import threading

import time
import json
import pprint
import hashlib
import struct
import re
import base64
import httplib
from threading import Thread
import Queue
import pts

ERR_SLEEP = 15
MAX_NONCE = 1000000L

settings = {}
pp = pprint.PrettyPrinter(indent=4)


class BitcoinRPC:
    OBJID = 1

    def __init__(self):
        self.host = settings['host']
        self.port = settings['port']
        username = settings['rpcuser']
        password = settings['rpcpass']
        authpair = "%s:%s" % (username, password)
        self.authhdr = "Basic %s" % (base64.b64encode(authpair))
        self.connect()
        #print "RPC init on %s:%d" % (host, port)

    def connect(self):
        self.conn = httplib.HTTPConnection(self.host, self.port, False, 15)

    def rpc(self, method, params=None, miner=None):
        self.OBJID += 1
        obj = {'version': '1.1',
               'method': method,
               'id': self.OBJID}
        if params is None:
            obj['params'] = []
        else:
            obj['params'] = params
        self.conn.request('POST', '/', json.dumps(obj),
                          {'Authorization': self.authhdr,
                           'Content-type': 'application/json'})

        prefix = ''
        if miner is not None:
            prefix = 'Miner %d hpm %f wpm %f queue %d/%d' % (miner.id,
                                                      miner.hashes / (time.time() - miner.start_time) * 60.0,
                                                      miner.works / (time.time() - miner.start_time) * 60.0,
                                                      miner.switch.work_queue.qsize(), miner.switch.result_queue.qsize())
        resp = self.conn.getresponse()
        if resp is None:
            print "%sJSON-RPC: no response" % prefix
            return None

        body = resp.read()
        resp_obj = json.loads(body)
        if resp_obj is None:
            print "%sJSON-RPC: cannot JSON-decode body" % prefix
            return None
        if 'error' in resp_obj and resp_obj['error'] is not None:
            return resp_obj['error']
        if 'result' not in resp_obj:
            print "%sJSON-RPC: no result in object" % prefix
            return None

        return resp_obj['result']

    def getwork(self, data=None, miner=None):
        try:
            return self.rpc('getwork', params=data, miner=miner)
        except:
            try:
                self.connect()
            except:
                pass

    def __enter__(self):
        return self

    def __exit__(self):
        try:
            self.conn.close()
        except:
            pass


class WorkFetcher(threading.Thread):
    def __init__(self, queue):
        super(WorkFetcher, self).__init__()
        self.daemon = True
        self.queue = queue
        self.rpc = BitcoinRPC()

    def run(self):
        while 1:
            try:
            #with BitcoinRPC() as rpc:
                getwork = self.rpc.getwork()
                if getwork is None:
                    continue
                static_data = getwork['data'].decode('hex')
                blk_hdr = static_data[:80]
                hash1 = hashlib.sha256(blk_hdr).digest()
                getwork['midstate'] = hashlib.sha256(hash1).digest()
                getwork['blk_hdr'] = blk_hdr
                self.queue.put(getwork, block=True)
            except:
                #import traceback
                #traceback.print_exc()
                pass


class WorkSubmitter(threading.Thread):
    def __init__(self, queue):
        super(WorkSubmitter, self).__init__()
        self.daemon = True
        self.queue = queue
        self.rpc = BitcoinRPC()
        self.stats_time = time.time()

    def run(self):
        while 1:
            try:
                result = self.queue.get(block=True)

                if self.stats_time < time.time() - 30:
                    self.stats_time = time.time()
                    print 'Worker %d hpm %f wpm %f queue %d/%d' % (
                        result['miner'].id,
                        result['miner'].hashes / (time.time() - result['miner'].start_time) * 60.0,
                        result['miner'].works / (time.time() - result['miner'].start_time) * 60.0,
                        result['miner'].switch.work_queue.qsize(), result['miner'].switch.result_queue.qsize())

                output = result['output']
                numpairs = struct.unpack('<Q', output[-8:])[0]
                colls = set()
                for p in xrange(numpairs):
                    p = struct.unpack('<II', output[p * 8:p * 8 + 8])
                    colls.add((p[0], p[1]))
                    colls.add((p[1], p[0]))
                if len(colls) == 0:
                    #print "No collisions, miner %d %f hpm" % (
                    #    result['miner'].id,
                    #    result['miner'].hashes / (time.time() - result['miner'].start_time) * 60.0)
                    continue

                targetbin = result['targetstr'].decode('hex')[-8:]
                target = struct.unpack('<Q', targetbin)[0]

                for coll in colls:
                    #if not 'miner' in result:
                    #    print str(result)
                    #print str(result['miner'].hashes)
                    result['miner'].hashes += 1
                    data = result['blk_hdr'] + struct.pack('<I', coll[0]) + struct.pack('<I', coll[1])
                    hash = hashlib.sha256(hashlib.sha256(data).digest()).digest()

                    l = struct.unpack('<Q', hash[-8:])[0]

                    if l < target:
                        prefix = 'Worker %d hpm %f wpm %f queue %d/%d' % (
                            result['miner'].id,
                            result['miner'].hashes / (time.time() - result['miner'].start_time) * 60.0,
                            result['miner'].works / (time.time() - result['miner'].start_time) * 60.0,
                            result['miner'].switch.work_queue.qsize(), result['miner'].switch.result_queue.qsize())
                        h = data.encode('hex')
                        #print "Submitting %s" % h
                        param_arr = [h]
                        #with BitcoinRPC() as rpc:
                        rpcresult = self.rpc.getwork(param_arr, miner=result['miner'])
                        print time.asctime(), "%s --> Upstream RPC result:" % prefix, rpcresult
            except:
                import traceback

                traceback.print_exc()
                pass


class Switch(object):
    def __init__(self, miner):
        self.miner = miner
        self.work_queue = Queue.Queue(settings['getwork_threads'] * 2)
        self.result_queue = Queue.Queue(settings['submit_threads'] * 4)
        self.fetchers = []
        self.submitters = []
        for _ in xrange(settings['getwork_threads']):
            fetcher = WorkFetcher(self.work_queue)
            fetcher.start()
            self.fetchers.append(fetcher)

        for _ in xrange(settings['submit_threads']):
            submitter = WorkSubmitter(self.result_queue)
            submitter.start()
            self.submitters.append(submitter)


class Miner:
    def __init__(self, id):
        self.id = id
        self.hasher = pts.PTSHasher(settings['platform'], self.id)
        self.start_time = -1
        self.hashes = 0
        self.works = 0
        self.switch = Switch(self)

    def iterate(self):
        work = self.switch.work_queue.get(block=True)
        if self.start_time == -1:
            self.start_time = time.time()

        if work is None:
            return
        if 'midstate' not in work or 'target' not in work:
            return
        output = self.hasher.processMidstate(work['midstate'])
        self.works += 1
        resdata = {'output': output,
                   'blk_hdr': work['blk_hdr'],
                   'targetstr': work['target'],
                   'miner': self}

        self.switch.result_queue.put(resdata, block=True)

    def loop(self):
        while True:
            self.iterate()


def miner_thread(id):
    miner = Miner(id)
    miner.loop()


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print "Usage: %s CONFIG-FILE" % sys.argv[0]
        sys.exit(1)

    f = open(sys.argv[1])
    for line in f:
        # skip comment lines
        m = re.search('^\s*#', line)
        if m:
            continue

        # parse key=value lines
        m = re.search('^(\w+)\s*=\s*(\S.*)$', line)
        if m is None:
            continue
        settings[m.group(1)] = m.group(2)
    f.close()

    if 'host' not in settings:
        settings['host'] = '127.0.0.1'
    if 'port' not in settings:
        settings['port'] = 8332
    if 'getwork_threads' not in settings:
        settings['getwork_threads'] = 1
    if 'hashmeter' not in settings:
        settings['hashmeter'] = 0
    if 'scantime' not in settings:
        settings['scantime'] = 30L
    if 'devices' not in settings:
        settings['devices'] = '0'
    if 'rpcuser' not in settings or 'rpcpass' not in settings:
        print "Missing username and/or password in cfg file"
        sys.exit(1)

    settings['platform'] = int(settings['platform'])
    settings['port'] = int(settings['port'])
    settings['hashmeter'] = int(settings['hashmeter'])
    settings['scantime'] = long(settings['scantime'])
    settings['getwork_threads'] = int(settings['getwork_threads'])
    settings['submit_threads'] = int(settings['submit_threads'])

    thr_list = []
    for dev_id in settings['devices'].split(','):
        thr_id = int(dev_id)
        p = Thread(target=miner_thread, args=(thr_id,))
        p.start()
        thr_list.append(p)
        time.sleep(1)            # stagger threads

    print time.asctime(), "Miner Starts - %s:%s" % (settings['host'], settings['port'])
    try:
        while True:
            raw_input()
    except KeyboardInterrupt:
        pass
    print time.asctime(), "Miner Stops - %s:%s" % (settings['host'], settings['port'])



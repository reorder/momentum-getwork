#!/usr/bin/python
#
# Momentum  miner by reorder, 2013


import os
import random
import pyopencl as cl
import struct
import time
import hashlib

HASHES_NUM = 0x800000
HASHES_SIZE = HASHES_NUM * 8 * 8
KEYS_NUM = HASHES_NUM * 8
KEYHASH_CAPACITY = KEYS_NUM * 2

KEYHASH_SIZE = KEYHASH_CAPACITY * 4
OUTPUT_SIZE = 8 * 0x100
RANDOMS = 1

def flipendian32(inmsg):
    return reduce(lambda x, y: x + inmsg[y:y+4][::-1], range(0, len(inmsg), 4), '')

def set_int_arg(k, pos, arg):
    k.set_arg(pos, struct.pack('<I', arg))

class PTSHasher(object):
    def __init__(self, platform_num, device_num):
        self.device = cl.get_platforms()[platform_num].get_devices()[device_num]
        self.device_name = self.device.name
        self.name = "PTSHasher:%d-%d" % (platform_num, device_num)
        self.ctx = cl.Context(devices=(self.device,))
        with open('pts.cl') as clfile:
            cltext = clfile.read()
        opts = '-DKEYHASH_CAPACITY=%d' % KEYHASH_CAPACITY
        self.prog = cl.Program(self.ctx, cltext).build(opts)
        print "%s initialized on device: %s type: %d, vendor: %s, LE: %d" % \
                    (self.name, self.device.name, self.device.type, self.device.vendor, self.device.endian_little)

        self.queue = cl.CommandQueue(self.ctx)

        self.sha512_fill = self.prog.pts_sha512_fill
        self.ksearch = self.prog.search_ht

        self.sha512_fill_ws = self.sha512_fill.get_work_group_info(cl.kernel_work_group_info.WORK_GROUP_SIZE, self.device)
        self.ksearch_ws = self.ksearch.get_work_group_info(cl.kernel_work_group_info.WORK_GROUP_SIZE, self.device)

        self.hashes_buf = cl.Buffer(self.ctx, 0, size=HASHES_SIZE)
        self.keyhash_buf = cl.Buffer(self.ctx, 0, size=KEYHASH_SIZE)
        self.output_buf = cl.Buffer(self.ctx, 0, size=OUTPUT_SIZE)


    def search(self, midstate):
        msg = flipendian32(midstate)

        for i in xrange(8):
            self.sha512_fill.set_arg(i, msg[i * 4:i * 4 + 4])
        self.sha512_fill.set_arg(8, self.hashes_buf)
        self.sha512_fill.set_arg(9, self.keyhash_buf)
        # t1 = time.time()
        cl.enqueue_nd_range_kernel(self.queue, self.sha512_fill, (HASHES_NUM,), (self.sha512_fill_ws,))
        self.queue.finish()
        # print "fill %f" % (time.time() - t1)

        output = bytearray(OUTPUT_SIZE)
        cl.enqueue_write_buffer(self.queue, self.output_buf, output)
        self.queue.finish()

        self.ksearch.set_arg(0, self.hashes_buf)
        self.ksearch.set_arg(1, self.keyhash_buf)
        self.ksearch.set_arg(2, self.output_buf)
        cl.enqueue_nd_range_kernel(self.queue, self.ksearch, (KEYS_NUM,), (self.ksearch_ws,))
        self.queue.finish()
        cl.enqueue_read_buffer(self.queue, self.output_buf, output)
        self.queue.finish()
        return str(output)

    def processMidstate(self, midstate):
        return self.search(midstate)

    def processData(self, data):
        hash1 = hashlib.sha256(data).digest()
        hash2 = hashlib.sha256(hash1).digest()
        return self.processMidstate(hash2)

    def verify(self, midstate, nonce1, nonce2):
        ndata1 = struct.pack('<I32s', nonce1 & ~7, midstate)
        ndata2 = struct.pack('<I32s', nonce2 & ~7, midstate)
        nhash1 = hashlib.sha512(ndata1).digest()
        nhash2 = hashlib.sha512(ndata2).digest()
        idx1 = nonce1 % 8
        idx2 = nonce2 % 8
        t1 = struct.unpack('<Q', nhash1[idx1 * 8:idx1 * 8 + 8])[0]
        t2 = struct.unpack('<Q', nhash2[idx2 * 8:idx2 * 8 + 8])[0]
        t1 >>= 14
        t2 >>= 14
        #print "%16x %16x" % (t1, t2)
        return t1 == t2


if __name__ == '__main__':
    hasher = PTSHasher(0, 0)

    count = 0
    gt1 = time.time()
    for i in range(300):
        midstate = ''.join(chr(random.randint(0, 255)) for x in range(32))
        t1 = time.time()
        output = hasher.processMidstate(midstate)
        numpairs = struct.unpack('<Q', output[-8:])[0]
        print numpairs
        colls = set()
        for p in xrange(numpairs):
            p = struct.unpack('<II', output[p * 8:p * 8 + 8])
            colls.add((p[0], p[1]))
            colls.add((p[1], p[0]))
        # print "%f %s: %s" % (time.time() - t1, midstate.encode('hex'), str(colls))
        print "%f %d" % (time.time() - t1, len(colls))
        if len(colls):
            count += len(colls)
            for coll in colls:
                if not hasher.verify(midstate, coll[0], coll[1]):
                    print "VERIFICATION FAILED %s %.x %.x" % (midstate.encode('hex'), coll[0], coll[1])
    totalTime = time.time() - gt1

    print "%d collisions in %f (%f hpm)" % (count / 2, totalTime, count / totalTime * 60)

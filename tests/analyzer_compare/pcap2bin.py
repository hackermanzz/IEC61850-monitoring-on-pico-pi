import struct, sys
def blocks(f):
    data=open(f,'rb').read(); off=0; le='<'
    tsres={}  # interface id -> units per second
    ifcount=0
    while off+12<=len(data):
        btype,blen=struct.unpack_from('<II',data,off)
        body=data[off+8:off+blen-4]
        if btype==0x0A0D0D0A:
            pass
        elif btype==1:  # IDB
            res=10**6
            o=8
            while o+4<=len(body):
                code,ln=struct.unpack_from('<HH',body,o); v=body[o+4:o+4+ln]
                if code==9 and ln>=1:
                    b=v[0]; res = 2**(b&0x7f) if b&0x80 else 10**b
                if code==0: break
                o+=4+((ln+3)&~3)
            tsres[ifcount]=res; ifcount+=1
        elif btype==6:  # EPB
            iface,th,tl,caplen,origlen=struct.unpack_from('<IIIII',body,0)
            ts=((th<<32)|tl); res=tsres.get(iface,10**6)
            yield int(ts*1_000_000//res), body[20:20+caplen]
        off+=blen
out=open(sys.argv[2],'wb'); n=0
for ts,pkt in blocks(sys.argv[1]):
    out.write(struct.pack('<QI',ts,len(pkt))); out.write(pkt); n+=1
print(n,'frames')

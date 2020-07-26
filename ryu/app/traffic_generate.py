from scapy.all import *
import threading
import time

def send_packet(x,count):
    s = time.time()
    print("sending between: ",x.src, x.dst)
    send([x]*count,verbose=False)
    print("time take = ", time.time() - s)
    print("done sending between: ",x.src, x.dst)


a=IP(dst="10.0.0.4",ttl=64)/ICMP()
b=IP(dst="10.0.0.2",ttl=64)/ICMP()

count = 2000
traffic_count = count
# th_a = threading.Thread(target=send_packet, args=(a,traffic_count))
# th_b = threading.Thread(target=send_packet, args=(b,traffic_count))
# th_c = threading.Thread(target=send_packet, args=(c,traffic_count))
print("starting target transfer")
start_time = time.time()

send_packet(a, count)
send_packet(b, count)

end_time = time.time()
print("Total time = ", end_time - start_time)


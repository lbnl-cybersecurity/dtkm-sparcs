#!/usr/bin/env python
import sys

sys.path.append("/usr/local/bro/lib/broctl")
from pybroker import *
from select import select
import pika
import json
import time
print "startup..."
credentials = pika.PlainCredentials('username', 'password')
parameters = pika.ConnectionParameters('yourserver.com',
                                       5672,
                                       '/',
                                       credentials)
#Broker vars
firsttime=True
brokermaster= None

des_helper1=["asreq:{status",
"status_code",
"not_valid_before",
"not_valid_after",
"key_length",
"serial",
"sig_alg",
"issuer",
"seen"
]

des_helper2=["asres:{status",
"status_code",
"not_valid_before",
"not_valid_after",
"key_length",
"serial",
"sig_alg",
"issuer",
"seen"
]

des_helper3=["tgtreq:{status",
"status_code",
"not_valid_before",
"not_valid_after",
"key_length",
"serial",
"sig_alg",
"issuer",
"seen"
]

des_helper4=["tgtres:{status",
"status_code",
"not_valid_before",
"not_valid_after",
"key_length",
"serial",
"sig_alg",
"issuer",
"seen"
]

des=["ip_src",
"ip_krb",
"status",
"reason",
"status_expires",
"uid",
]

def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""


def find_between_r( s, first, last ):
    try:
        start = s.rindex( first ) + len( first )
        end = s.rindex( last, start )
        return s[start:end]
    except ValueError:
        return ""


des +=des_helper1+des_helper2+des_helper3+des_helper4

des=["{\"ip_src\"",
 "\"ip_dst\"",
 "\"fc_req\"",
 "\"port_src\"",
 "\"port_dst\"",
 "\"fc_res\"",
 "\"@timestamp\"",
 ]


try:
    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()
    print("rabbit connected")
    channel.exchange_declare(exchange='bro2rabbit', exchange_type='topic', passive=False, durable=True, auto_delete=False, internal=False, arguments=None)
    channel.queue_declare(queue='test-bro2rabbit', passive=False, durable=True, exclusive=False, auto_delete=False, arguments=None)
    channel.queue_bind(queue='test-bro2rabbit', exchange='bro2rabbit', routing_key='*', arguments=None)
  

    def on_message(channel, method_frame, header_frame, body):
        print "recieved a message"
        print method_frame.delivery_tag
        print body




    epc = endpoint("pyhton_bro2rabbit")
    #ocsq = epc.outgoing_connection_status()
    #epc.listen(9999, "127.0.0.1")
    #ocsq = epc.incoming_connection_status().need_pop()


    epc.peer("127.0.0.1", 9999, 1)


    #brokermaster = master_create(epc,"rabbitmaster")
    #brokermaster = clone_create(epc,"rabbitmaster",0)


    mql = message_queue("bro/event", epc)

    print "Bro2rabbit.py now connecting..."
    while True:
        select([mql.fd()], [], [])
        msgs = mql.want_pop()
        
        if firsttime:
            print "Now connected to BRO for the first time..."
            print ""
            brokermaster = frontend(epc,"rabbitmaster")
            
            firsttime=False

        #print brokermaster.lookup(data(1)).data()
        #print brokermaster.keys()
        for m in msgs:

           
            if True:
                d=m[1]

                #print "got a message from bro refering to the content with key:",str(d)

                rabbitmsg=str(d)
                rabbitmsg=rabbitmsg.replace("(","")
                #rabbitmsg=rabbitmsg.replace(")","\"}")
                #rabbitmsg=rabbitmsg.replace(")","\"}")
                rabbitmsg = rabbitmsg.replace(")", "")
                sp=rabbitmsg.split()
                print(sp[-1])
                subseconds=sp[-1].split(".")
                sp[-1] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.localtime(float(sp[-1])))
              
              
                #%sp.replace("subsec",str(subseconds[-1]))



                sp = ["\""+x+"\"" for x in sp]
                output=map(lambda (x,y): x+":"+y, zip(des, sp))
                sp2=[]
                for j in output:
                    j = j.replace(",\"", "")
                    sp2.append(j)
                    


                output= ', '.join(sp2)
                output=output.replace("subsec",str(subseconds[-1]))
                output= output.replace(",\"","\"")
                output = output.replace("{","")
               
                elastictype="{\"type\":\"scada2bro, "
                elasticsystem="\"system\":\"scada, "
                output = elastictype+elasticsystem+output+"}"
                
                output= output.replace(",","\",")
                
                print "message sent to rabbit is", output
                try:
                    
                    channel.basic_publish(exchange='bro2rabbit', routing_key='bro2rabbit', body=output, properties=None, mandatory=False, immediate=False)
                except pika.exceptions.ConnectionClosed: #we like got into a timeout with the rabbit connection reconnect and try again it seems that rabbitmq decreased the default timeout from 10min to just one minute making this nessecary
                    connection = pika.BlockingConnection(parameters)
                    channel = connection.channel()
                    channel.basic_publish(exchange='bro2rabbit', routing_key='bro2rabbit', body=output, properties=None, mandatory=False, immediate=False)



finally:
    try:
        connection.close()
        print "conntection to rabbit closed gracefully"
    except:
        print "no rabbit connection to close, exiting"

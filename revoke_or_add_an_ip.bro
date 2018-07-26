@load base/protocols/krb/
@load base/files/x509/
@load base/protocols/conn/
@load base/protocols/ssl/main.bro 


const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "manualremover";
global msg_count = 0;
global h: opaque of Broker::Handle;
global a: string;
global waitforme: bool=F;
global my_event: event(msg: string, c: count);
global centraladdremote: event(ip: addr, reasonin: string, expire: time);
global centralremoveremote: event(ip: addr, reasonin: string, expire: time);


type mytest: record{
	a: string &default = "doll";
	b: string &default= "T";
};

type com: record{
        status: string &default = "U";
	status_code: int &optional;
        not_valid_before: time &optional;
        not_valid_after: time &optional;
        key_length: int &optional;
        serial: string &optional;
        sig_alg: string &optional;
	issuer: string &optional;
	seen: time &optional;
	
};
type lbl: record{
	ip_src: addr &default= to_addr("0.0.0.0");
	ip_krb: addr &default= to_addr("0.0.0.0");
	status: string &default = "U";
        reason: string &optional;
	status_expires: time &optional;
	uid: string &optional;
	as_req: com &default = com($status="U");
	as_res: com &default = com($status="U");
	tgt_req: com &default = com($status="U");
	tgt_res: com &default = com($status="U");
};


type myrecordset: set[mytest];
global lbltable: table[addr] of lbl;
#global lblvar: lbltable; #([["1"]] =$status="W",[["2"]]=$status="x");
global my_event2: event(msg: mytest);
global my_event3: event(msg: myrecordset);
global my_event4: event(msg: lbl);
global centralautoadd: event(msg: lbl);

global mytable: table[string] of mytest;



event new_connection(c: connection ){
	#print c$id$resp_p;
	


}
event connection_first_ACK(c: connection){
#event connection_established(c: connection ){ #when syn and ack packet recieved in a TCP connection
	local anyerror=0;
	local srcerror="OK";
	local dsterror="OK";
	if(c$id$resp_p==102/tcp){
		print "a new connection on port 102 has been established \n";

		print c;

		if (c$id$orig_h in lbltable){
			

		if(lbltable[(c$id$orig_h)]$status!= "OK"){
#			if(lbltable[(c$id$orig_h)]$status_expires>c$start_time){
#				print "Keberos ID of source expired before connection began.";
#				anyerror=1;
#
#			}
#			else {
#				print "source ok";
#			}
		}
		else {
			print "source has no valid key";
			anyerror=1;
		}
		
		}
		else { 
			print "source",c$id$orig_h,"did never contact KRB";
			anyerror=1;
		}
		
		if (c$id$resp_h in lbltable){

		if(lbltable[(c$id$resp_h)]$status!= "OK"){
#                       if(lbltable[(c$id$resp_h)]$status_expires>c$start_time){
#                                print "Keberos ID of destination expired before connection began.";
#				anyerror=1;
#
#                       }
#                        else {
#                                print "desination ok";
#                        }
                }
                else {
                        print "destination has no valid key";
			anyerror=1;
                }
		
		}
		else{
			print "destination", c$id$resp_h,"did never contact KRB sucessfully";
			anyerror=1;
		}

	if (anyerror==1){
		print "we have found an error";
		#todo send out to rabbit
	}
	else {
		print "new connection on port 102 fully ok!!!!!";
	}
	}

}

function do_lookup(key: string)
        {
#        when ( local res = Broker::lookup(h, Broker::data(key)) )
#                {
#                print "lookup",key,res, Broker::refine_to_string(res$result);
#		a= Broker::refine_to_string(res$result);
#		return;
#                }
#        timeout 10000sec
#                { print "timeout", key; }
	

        }


event krb_error(c: connection, msg: KRB::Error_Msg) &priority=5{
# print " ";
 print "KRB_ERROR";
 print msg;

        if (lbltable[(c$id$orig_h)]$uid!=c$uid){
		print "connection uid dont match";
		return;
	}
	if (lbltable[(c$id$orig_h)]?$as_res){
	lbltable[(c$id$orig_h)]$as_res$status_code=msg$error_code;
	lbltable[(c$id$orig_h)]$as_res$status=KRB::error_msg[msg$error_code];
	lbltable[(c$id$orig_h)]$as_res$seen=network_time();
	lbltable[(c$id$orig_h)]$status= "FAILED";
	if (!lbltable[(c$id$orig_h)]?$reason){
		lbltable[(c$id$orig_h)]$reason=KRB::error_msg[msg$error_code];
		}
	}


# print "next is the connection info";
# print c;
}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate){
 #We get this if the test was successful
 #print " ";
 #print "x509 certificate sucessfull";
 #print cert;
 #print "";
 #print "cert ref";
 #print cert_ref;
}

event x509_ext_basic_constraints(f: fa_file, ext: X509::BasicConstraints){
#print "x509 test";
}

event centraladd(ip: addr, reasonin: string, expire: time){
	#if (ip in lbltable[(ip)]){
	#	print "already saw user";
	#}
	#else{
	print "Manually added the following ip";
	print ip;
	lbltable[(ip)] = lbl($ip_src=(ip));
	#}
	lbltable[(ip)]$as_res$status_code= 0;
	lbltable[(ip)]$as_res$status= "ok";
	lbltable[(ip)]$as_req$status_code= 0;
	lbltable[(ip)]$as_req$status= "ok";
	lbltable[(ip)]$tgt_res$status_code= 0;
	lbltable[(ip)]$tgt_res$status= "ok";
	lbltable[(ip)]$tgt_req$status_code= 0;
	lbltable[(ip)]$tgt_req$status= "ok";
	lbltable[(ip)]$tgt_req$status_code= 0;
	lbltable[(ip)]$status= "ok";
	lbltable[(ip)]$reason= reasonin;
	lbltable[(ip)]$status_expires= expire;
	

}

event krb_as_request(c: connection, msg: KRB::KDC_Request) &priority=-20
        {
# 	print " ";
	print "got as req_marked";
		
#	if (c$id$orig_h in lbltable[(c$id$orig_h)]){
#		print "already saw user";
#	}
#	else{
	lbltable[(c$id$orig_h)] = lbl($ip_src=(c$id$orig_h));
#	}	

        local info: KRB::Info;
	
	if ( c?$krb && c$krb$logged )
                return;


        if ( !c?$krb )
                {
                info$ts  = network_time();
                info$uid = c$uid;
                info$id  = c$id;
                }
        else
                info = c$krb;

        info$request_type = "AS";
        info$client = fmt("%s/%s", msg$client_name, msg$service_realm);
        info$service = msg$service_name;

        if ( msg?$from )
                info$from = msg$from;

        info$till = msg$till;

        info$forwardable = msg$kdc_options$forwardable;
        info$renewable = msg$kdc_options$renewable;
	lbltable[(c$id$orig_h)]$ip_krb=c$id$resp_h;
	lbltable[(c$id$orig_h)]$as_req$status="reqested";
	lbltable[(c$id$orig_h)]$as_req$seen=network_time();
	lbltable[(c$id$orig_h)]$uid=c$uid;


#	print "INFO";
#	print info;
	if (info?$client_cert){
	 	if(info$client_cert?$x509){
		lbltable[(c$id$orig_h)]$as_req$not_valid_before=info$client_cert$x509$certificate$not_valid_before;
		lbltable[(c$id$orig_h)]$as_req$not_valid_after=info$client_cert$x509$certificate$not_valid_after;
		lbltable[(c$id$orig_h)]$as_req$key_length=info$client_cert$x509$certificate$key_length;
		lbltable[(c$id$orig_h)]$as_req$serial=info$client_cert$x509$certificate$serial;
		lbltable[(c$id$orig_h)]$as_req$sig_alg=info$client_cert$x509$certificate$sig_alg;
		lbltable[(c$id$orig_h)]$as_req$issuer=info$client_cert$x509$certificate$subject;
		lbltable[(c$id$orig_h)]$as_req$status="ok";
		}
	}
	else{
	lbltable[(c$id$orig_h)]$as_req$status="CERT FAILED";
	lbltable[(c$id$orig_h)]$status="FAILED";
	lbltable[(c$id$orig_h)]$reason="as-req cert  FAILED";

	}
	#print lbltable;
	Broker::send_event("bro/events/my_central", Broker::event_args(centralautoadd,lbltable[(c$id$orig_h)]));
	
	#print info;
	#print "connection";
	#print c;
        }


event krb_tgs_request(c: connection, msg: KRB::KDC_Request) &priority=5
        {

	#print " ";
	print "got KRB TGS request";
	
        if ( c?$krb && c$krb$logged )
                return;

        local info: KRB::Info;
        info$ts  = network_time();
        info$uid = c$uid;
        info$id  = c$id;
        info$request_type = "TGS";
        info$service = msg$service_name;
        if ( msg?$from ) info$from = msg$from;
        info$till = msg$till;

        info$forwardable = msg$kdc_options$forwardable;
        info$renewable = msg$kdc_options$renewable;

        lbltable[(c$id$orig_h)]$status="tgsrequest";
        lbltable[(c$id$orig_h)]$tgt_req$seen=network_time();

        lbltable[(c$id$orig_h)]$tgt_req$status="ok";
        lbltable[(c$id$orig_h)]$tgt_req$status_code=0;

	Broker::send_event("bro/events/my_central", Broker::event_args(centralautoadd,lbltable[(c$id$orig_h)]));

	print "TGS req processed";
	#print info;
        }

event krb_as_response(c: connection, msg: KRB::KDC_Response) &priority=5
        {
	print "";
	print "got KRB as response";
        local info: KRB::Info;
	

        if ( c?$krb && c$krb$logged )
                return;

        if ( c?$krb )
                info = c$krb;

        if ( ! info?$ts )
                {
                info$ts  = network_time();
                info$uid = c$uid;
                info$id  = c$id;
                }

        if ( ! info?$client )
                info$client = fmt("%s/%s", msg$client_name, msg$client_realm);

        info$service = msg$ticket$service_name;
        info$cipher  = KRB::cipher_name[msg$ticket$cipher];
        info$success = T;
        if (lbltable[(c$id$orig_h)]$uid!=c$uid){
		print "connection uid dont match is as response";
		return;
	}
	lbltable[(c$id$orig_h)]$as_res$status="response";
	lbltable[(c$id$orig_h)]$as_res$seen=network_time();
	
	if (info$success == T){	
        if (info?$server_cert){
                if(info$server_cert?$x509){
                lbltable[(c$id$orig_h)]$as_res$not_valid_before=info$server_cert$x509$certificate$not_valid_before;
                lbltable[(c$id$orig_h)]$as_res$not_valid_after=info$server_cert$x509$certificate$not_valid_after;
                lbltable[(c$id$orig_h)]$as_res$key_length=info$server_cert$x509$certificate$key_length;
                lbltable[(c$id$orig_h)]$as_res$serial=info$server_cert$x509$certificate$serial;
                lbltable[(c$id$orig_h)]$as_res$sig_alg=info$server_cert$x509$certificate$sig_alg;
                lbltable[(c$id$orig_h)]$as_res$issuer=info$server_cert$x509$certificate$subject;
                lbltable[(c$id$orig_h)]$as_res$status="ok";
		lbltable[(c$id$orig_h)]$as_res$not_valid_before=info$server_cert$x509$certificate$not_valid_before;

                }
        }
        else{
#        lbltable[(c$id$orig_h)]$as_res$status="CERT FAILED";
#        lbltable[(c$id$orig_h)]$status="FAILED";
#        lbltable[(c$id$orig_h)]$reason="as-res cert  FAILED";
        lbltable[(c$id$orig_h)]$as_res$status="ok";
        lbltable[(c$id$orig_h)]$status="ok";
        lbltable[(c$id$orig_h)]$reason="no server cert in stream but successfull";


        }
	}
	else{
	#no success
        lbltable[(c$id$orig_h)]$as_res$status="No success FAILED";
        lbltable[(c$id$orig_h)]$status="FAILED";
        lbltable[(c$id$orig_h)]$reason="as-res no success  FAILED";

	}
	
	

#	Broker::send_print("bro/events/test", "AS result true");	
#	Broker::send_print("bro/events/test", "AS response OK from hostname " +addr_to_ptr_name(c$id$orig_h));	
	#print info;
	#print "";
	#print "now the connection info";
	#print c;
		Broker::send_event("bro/events/my_central", Broker::event_args(centralautoadd,lbltable[(c$id$orig_h)]));

        }


event krb_tgs_response(c: connection, msg: KRB::KDC_Response) &priority=5
        {
#	print "";
	print "got krb tgs response";
        local info: KRB::Info;

        if ( c?$krb && c$krb$logged )
                return;

        if ( c?$krb )
                info = c$krb;

        if ( ! info?$ts )
                {
                info$ts  = network_time();
                info$uid = c$uid;
                info$id  = c$id;
                }

        if ( ! info?$client )
                info$client = fmt("%s/%s", msg$client_name, msg$client_realm);

        info$service = msg$ticket$service_name;
        info$cipher  = KRB::cipher_name[msg$ticket$cipher];
        info$success = T;

#		print "INFO";
#	print info;
#	print "INFO DONE";


	# if (lbltable[(c$id$orig_h)]$uid!=c$uid){
        #        print "connection uid dont match in tgs response"; #this is normal as TGT is a seperate connection
        #        return;
        #}
        lbltable[(c$id$orig_h)]$status="tgsresponse";
        lbltable[(c$id$orig_h)]$tgt_res$seen=network_time();

        lbltable[(c$id$orig_h)]$tgt_res$status="ok";
        lbltable[(c$id$orig_h)]$tgt_res$status_code=0;
        lbltable[(c$id$orig_h)]$status="ok";
        lbltable[(c$id$orig_h)]$reason="TGT_granted";
	if (!lbltable[(c$id$orig_h)]$as_req?$not_valid_after){
        	lbltable[(c$id$orig_h)]$status_expires=lbltable[(c$id$orig_h)]$as_req$not_valid_after;
	}
	else{
	}


#        if (info?$server_cert){
#                if(info$server_cert?$x509){
#                lbltable[(c$id$orig_h)]$tgt_res$not_valid_before=info$server_cert$x509$certificate$not_valid_before;
#                lbltable[(c$id$orig_h)]$tgt_res$key_length=info$server_cert$x509$certificate$key_length;
#                lbltable[(c$id$orig_h)]$tgt_res$serial=info$server_cert$x509$certificate$serial;
#                lbltable[(c$id$orig_h)]$tgt_res$sig_alg=info$server_cert$x509$certificate$sig_alg;
#                lbltable[(c$id$orig_h)]$tgt_res$issuer=info$server_cert$x509$certificate$subject;
#                lbltable[(c$id$orig_h)]$tgt_res$status="ok";
#                }
#        }
#        else{
#        lbltable[(c$id$orig_h)]$tgt_res$status="CERT FAILED";
#        lbltable[(c$id$orig_h)]$status="FAILED";
#        lbltable[(c$id$orig_h)]$reason="tgt-res cert  FAILED";
#
#        }


#        lbltable[(c$id$orig_h)]$tgt_res$not_valid_before=info$server_cert$x509$certificate$not_valid_before;
	Broker::send_event("bro/events/my_central", Broker::event_args(centralautoadd,lbltable[(c$id$orig_h)]));







	print "tgs resp sucessful processed";
#	print info;
#	print "PRINT COMPLETE";

        }


 event bro_init(){
 print "startup";
 print "enableing broker";
 Broker::enable();
 Broker::subscribe_to_prints("bro/print/");
 #Broker::listen(broker_port, "127.0.0.1");  #uncomment this to make bro the server
 Broker::connect("127.0.0.1", broker_port, 1sec);
h = Broker::create_master("central");
Broker::insert(h, Broker::data("1"), Broker::data(123));
local myset: set[string] = {"a", "b", "c"};
local myvec: vector of string = {"alpha", "beta", "gamma"};
local myrecord2 = myrecordset([$b="1"],[$b="2"]);
add myrecord2[mytest ($b="t")];
#local myvec2: vector of field = {field: string: "a", field: string: "b"};
Broker::insert(h, Broker::data("myset"), Broker::data(myset));
#Broker::insert(h, Broker::data("myvec"), Broker::data(myvec));
local myrecord: mytest = record($a="12");
Broker::insert(h, Broker::data("myvec"), Broker::data(myvec));
Broker::insert(h, Broker::data("fun"),Broker::data(myrecord2));

#mytable["1"] = mytest($b="1");

#print mytable;
#lbltable[to_addr("192.168.2.1")] = lbl($status="ok");
#lbltable[to_addr("192.168.2.1")]$as_req=com($status_code="test");
#lbltable[to_addr("192.168.2.1")]$as_req$status_code="test3";
#print lbltable[to_addr("192.168.2.1")]$as_res$status_code;
#print lbltable;

}





event Broker::incoming_connection_established(peer_name: string)
        {
	if (peer_name != "central"){
        print "Broker::incoming_connection_established", peer_name;
        print "sending all current connections";
#        Broker::send_print("bro/events/test", "1");
#        Broker::send_print("bro/events/test", "myset");
#        Broker::send_print("bro/events/test", "myvec");
#	Broker::send_event("bro/events/my_central", Broker::event_args(my_event, "hi", 0));
#        Broker::send_print("bro/events/test", "fun");
	local mytest2 = mytest($b="1");
	local myrecord2 = myrecordset([$b="1"],[$b="2"]);
	#print myrecord2;
	for (d in myrecord2){
		
		#print d;
		#print d$b;
		#print "stop";
}
#	print myrecord2[mytest($b="1")]$a;	
#	Broker::send_event("bro/events/my_event", Broker::event_args(my_event3,myrecord2[mytest($b="1")]));
	for (t in lbltable){
	#print "table";
	#print t;
	Broker::send_event("bro/events/my_event", Broker::event_args(centralautoadd,lbltable[t]));
	print lbltable[t];
}
#	Broker::send_event("bro/events/my_event", Broker::event_args(centralautoadd,lbltable[to_addr("192.168.2.1")]));
#	Broker::send_event("bro/events/my_event", Broker::event_args(my_event2,mytest2));
	
}
        }

event Broker::print_handler(msg: string)
        {
        ++msg_count;
        print "got print message", msg;

        if ( msg_count == 3 )
                #terminate();

        print "sending back hello world";
        Broker::send_print("bro/events/test", "hello world");

        }


event Broker::incoming_connection_broken(peer_name: string)
        {
        print "Broker::incoming_connection_broken", peer_name;

        #terminate();
        }


event bro_done(){
 print "finished";
}


event krb_tgs_response(c: connection, msg: KRB::KDC_Response){
# print "krb_tgs_resp";

 #print msg;
}


event krb_safe(c: connection, is_orig: bool, msg: KRB::SAFE_Msg){
 #A Kerberos 5 Safe Message as defined in RFC 4120. This is a safe (checksummed) application message 

 print "krb_save_msg__ap";
#print msg;
 
}

event nonexist(){
 print "a";
}



event Broker::outgoing_connection_established(peer_address: string,
                                            peer_port: port,
                                            peer_name: string)
        {
	print "OUTGOING ESTABLISHED";
        print "Broker::outgoing_connection_established",
              peer_address, peer_port, peer_name;
#        h = Broker::create_frontend("rabbitmaster");

	when ( local res = Broker::keys(h) )
                {
                print "remote keys", res;
		
		do_lookup(Broker::refine_to_string(Broker::vector_lookup(res$result, 0)));
		
		
                }
        timeout 10min #seems that the sec actually stands for ms
               { print "timeout"; }
	print "sending removeevent";
	Broker::send_event("bro/central/my_event", Broker::event_args(centraladdremote,to_addr("123.123.123.123"),"manual_add_from_central",network_time()));
	Broker::send_event("bro/central/my_event", Broker::event_args(centralremoveremote,to_addr("12.12.12.12"),"manual_revoke_from_central",network_time()));

#        event do_write();
        }

event Broker::outgoing_connection_broken(peer_address: string,
                                       peer_port: port)
        {
#        terminate();
        }


event rdp_connect_request(c: connection, cookie: string)
{	
	print "rdp req";
	#print fmt("%s.%d-%s.%d: %s: %s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, "Username:", cookie);
}

event rdp_negotiation_response(c: connection, security_protocol: count)
{
	print "rdp  resp";
	#print fmt("%s.%d-%s.%d: %s: %s", c$id$resp_h, c$id$resp_p, c$id$orig_h, c$id$orig_p, "Security Protocol:", c$rdp$security_protocol);
}

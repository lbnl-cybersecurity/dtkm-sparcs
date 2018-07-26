@load base/protocols/krb/
@load base/files/x509/
@load base/protocols/conn/
#@load base/protocols/ssl/main.bro 
@load base/protocols/ssl/
@load policy/protocols/ssl/validate-certs.bro
@load policy/misc/scan.bro

const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "Bro_for_rabbit2bro";
global msg_count = 0;
global h: opaque of Broker::Handle;
global a: string;
global waitforme: bool=F;
global my_event: event(msg: string, c: count);
global root_certs: table[string] of string ;
@load base/protocols/ssl/mozilla-ca-list.bro


#root_certs["CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE"] = "\x30\x82\x03\x75\x30\x82\x02\x5D\xA0\x03\x02\x01\x02\x02\x0B\x04\x00\x00\x00\x00\x01\x15\x4B\x5A\xC3\x94\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x30\x57\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x42\x45\x31\x19\x30\x17\x06\x03\x55\x04\x0A\x13\x10\x47\x6C\x6F\x62\x61\x6C\x53\x69\x67\x6E\x20\x6E\x76\x2D\x73\x61\x31\x10\x30\x0E\x06\x03\x55\x04\x0B\x13\x07\x52\x6F\x6F\x74\x20\x43\x41\x31\x1B\x30\x19\x06\x03\x55\x04\x03\x13\x12\x47\x6C\x6F\x62\x61\x6C\x53\x69\x67\x6E\x20\x52\x6F\x6F\x74\x20\x43\x41\x30\x1E\x17\x0D\x39\x38\x30\x39\x30\x31\x31\x32\x30\x30\x30\x30\x5A\x17\x0D\x32\x38\x30\x31\x32\x38\x31\x32\x30\x30\x30\x30\x5A\x30\x57\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x42\x45\x31\x19\x30\x17\x06\x03\x55\x04\x0A\x13\x10\x47\x6C\x6F\x62\x61\x6C\x53\x69\x67\x6E\x20\x6E\x76\x2D\x73\x61\x31\x10\x30\x0E\x06\x03\x55\x04\x0B\x13\x07\x52\x6F\x6F\x74\x20\x43\x41\x31\x1B\x30\x19\x06\x03\x55\x04\x03\x13\x12\x47\x6C\x6F\x62\x61\x6C\x53\x69\x67\x6E\x20\x52\x6F\x6F\x74\x20\x43\x41\x30\x82\x01\x22\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01\x0F\x00\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xDA\x0E\xE6\x99\x8D\xCE\xA3\xE3\x4F\x8A\x7E\xFB\xF1\x8B\x83\x25\x6B\xEA\x48\x1F\xF1\x2A\xB0\xB9\x95\x11\x04\xBD\xF0\x63\xD1\xE2\x67\x66\xCF\x1C\xDD\xCF\x1B\x48\x2B\xEE\x8D\x89\x8E\x9A\xAF\x29\x80\x65\xAB\xE9\xC7\x2D\x12\xCB\xAB\x1C\x4C\x70\x07\xA1\x3D\x0A\x30\xCD\x15\x8D\x4F\xF8\xDD\xD4\x8C\x50\x15\x1C\xEF\x50\xEE\xC4\x2E\xF7\xFC\xE9\x52\xF2\x91\x7D\xE0\x6D\xD5\x35\x30\x8E\x5E\x43\x73\xF2\x41\xE9\xD5\x6A\xE3\xB2\x89\x3A\x56\x39\x38\x6F\x06\x3C\x88\x69\x5B\x2A\x4D\xC5\xA7\x54\xB8\x6C\x89\xCC\x9B\xF9\x3C\xCA\xE5\xFD\x89\xF5\x12\x3C\x92\x78\x96\xD6\xDC\x74\x6E\x93\x44\x61\xD1\x8D\xC7\x46\xB2\x75\x0E\x86\xE8\x19\x8A\xD5\x6D\x6C\xD5\x78\x16\x95\xA2\xE9\xC8\x0A\x38\xEB\xF2\x24\x13\x4F\x73\x54\x93\x13\x85\x3A\x1B\xBC\x1E\x34\xB5\x8B\x05\x8C\xB9\x77\x8B\xB1\xDB\x1F\x20\x91\xAB\x09\x53\x6E\x90\xCE\x7B\x37\x74\xB9\x70\x47\x91\x22\x51\x63\x16\x79\xAE\xB1\xAE\x41\x26\x08\xC8\x19\x2B\xD1\x46\xAA\x48\xD6\x64\x2A\xD7\x83\x34\xFF\x2C\x2A\xC1\x6C\x19\x43\x4A\x07\x85\xE7\xD3\x7C\xF6\x21\x68\xEF\xEA\xF2\x52\x9F\x7F\x93\x90\xCF\x02\x03\x01\x00\x01\xA3\x42\x30\x40\x30\x0E\x06\x03\x55\x1D\x0F\x01\x01\xFF\x04\x04\x03\x02\x01\x06\x30\x0F\x06\x03\x55\x1D\x13\x01\x01\xFF\x04\x05\x30\x03\x01\x01\xFF\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14\x60\x7B\x66\x1A\x45\x0D\x97\xCA\x89\x50\x2F\x7D\x04\xCD\x34\xA8\xFF\xFC\xFD\x4B\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x03\x82\x01\x01\x00\xD6\x73\xE7\x7C\x4F\x76\xD0\x8D\xBF\xEC\xBA\xA2\xBE\x34\xC5\x28\x32\xB5\x7C\xFC\x6C\x9C\x2C\x2B\xBD\x09\x9E\x53\xBF\x6B\x5E\xAA\x11\x48\xB6\xE5\x08\xA3\xB3\xCA\x3D\x61\x4D\xD3\x46\x09\xB3\x3E\xC3\xA0\xE3\x63\x55\x1B\xF2\xBA\xEF\xAD\x39\xE1\x43\xB9\x38\xA3\xE6\x2F\x8A\x26\x3B\xEF\xA0\x50\x56\xF9\xC6\x0A\xFD\x38\xCD\xC4\x0B\x70\x51\x94\x97\x98\x04\xDF\xC3\x5F\x94\xD5\x15\xC9\x14\x41\x9C\xC4\x5D\x75\x64\x15\x0D\xFF\x55\x30\xEC\x86\x8F\xFF\x0D\xEF\x2C\xB9\x63\x46\xF6\xAA\xFC\xDF\xBC\x69\xFD\x2E\x12\x48\x64\x9A\xE0\x95\xF0\xA6\xEF\x29\x8F\x01\xB1\x15\xB5\x0C\x1D\xA5\xFE\x69\x2C\x69\x24\x78\x1E\xB3\xA7\x1C\x71\x62\xEE\xCA\xC8\x97\xAC\x17\x5D\x8A\xC2\xF8\x47\x86\x6E\x2A\xC4\x56\x31\x95\xD0\x67\x89\x85\x2B\xF9\x6C\xA6\x5D\x46\x9D\x0C\xAA\x82\xE4\x99\x51\xDD\x70\xB7\xDB\x56\x3D\x61\xE4\x6A\xE1\x5C\xD6\xF6\xFE\x3D\xDE\x41\xCC\x07\xAE\x63\x52\xBF\x53\x53\xF4\x2B\xE9\xC7\xFD\xB6\xF7\x82\x5F\x85\xD2\x41\x18\xDB\x81\xB3\x04\x1C\xC5\x1F\xA4\x80\x6F\x15\x20\xC9\xDE\x0C\x88\x0A\x1D\xD6\x66\x55\xE2\xFC\x48\xC9\x29\x26\x69\xE0";;


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
#global centraladdremote: event(ip: addr, reasonin: string, expire: time);

global mytable: table[string] of mytest;



event new_connection(c: connection ){
	#print c$id$resp_p;
	


}
event connection_first_ACK(c: connection){
#event connection_established(c: connection ){ #when syn and ack packet recieved in a TCP connection
	local anyerror=0;
	local srcerror="OK";
	local dsterror="OK";
	local ignoredest=F;
	local waitingfordestination=F;
	if(c$id$resp_p==102/tcp){
		print "a new connection on port 102 has been established \n";

		#print c;

		if (c$id$orig_h in lbltable){
			
		print "status of source is", lbltable[(c$id$orig_h)]$status;		
		print "status of destination is", lbltable[(c$id$resp_h)]$status;		

		if(lbltable[(c$id$orig_h)]$status == "revoked"){
			print "key is revoked";
			anyerror=1;
}
		if(lbltable[(c$id$orig_h)]$status == "ok"){
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
		
		#if (ignoredest==F){		
		if(lbltable[(c$id$resp_h)]$status!= "OK"){
		#	print "destination failed KRB for new connection on port 102";
		#	anyerror=1;
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
                     #   print "destination has no valid key";
		#	anyerror=1;
                }
		
		}
		else{
			#print "destination", c$id$resp_h,"did never contact KRB sucessfully, giving timeout to do so";
			#waitingfordestination=T;
			# when ( "ok" == lbltable[(c$id$resp_h)]$status)
            		#{
	    		#	print "Key received in time; connection accepted to ip";
	   		#	 print c$id$resp_h;
           		#	# return 0;
           		# }
     			# timeout 2 sec
     			# {
			#    print "NO KEY RECIEVED IN TIME FOR DESTINATION";
			#    print c$id$resp_h;
		
		         #   anyerror = 1;
            		#}

			#anyerror=1;
		}

#	}
	if (anyerror==1){
		print "we have found an error";
		#todo send out to rabbit
	}
	else { if(waitingfordestination==F){
		print "new connection on port 102 fully ok!!!!!";
	}
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
# if (msg$error_code != 6){
# if (msg$error_code != 7){
 print "KRB_ERROR, from IP ", c$id$orig_h;
 print msg;
 

        if (lbltable[(c$id$orig_h)]$uid!=c$uid){
		print "connection uid dont match";
		return;
	}
	if (lbltable[(c$id$orig_h)]?$as_res){
	lbltable[(c$id$orig_h)]$as_res$status_code=msg$error_code;
	lbltable[(c$id$orig_h)]$as_res$status=KRB::error_msg[msg$error_code];
	lbltable[(c$id$orig_h)]$as_res$seen=network_time();
	}
	lbltable[(c$id$orig_h)]$status= "FAILED";
	if (!lbltable[(c$id$orig_h)]?$reason){
		lbltable[(c$id$orig_h)]$reason=KRB::error_msg[msg$error_code];
		}

#}
#else{ print "Code 7";
#}

#}
#else { print "Code 6";}
# print "next is the connection info";
# print c;
}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate){
 #We get this if the test was successful
 #print " ";
 print "x509 certificate sucessfull";
 #print cert;
 local chain: vector of opaque of x509 = vector();
 chain[0]=cert_ref;
 local root:table[string] of string; 
 root["emailAddress=rgentz@lbl.gov,CN=Reinhard,O=LBL,L=SFO,ST=Rainer,C=DE"] = "\x30\x82\x03\xAB\x30\x82\x02\x93\xA0\x03\x02\x01\x02\x02\x09\x00\xD9\x2A\xBF\x14\xBE\xC1\x88\x1C\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B\x05\x00\x30\x6C\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x44\x45\x31\x0F\x30\x0D\x06\x03\x55\x04\x08\x0C\x06\x52\x61\x69\x6E\x65\x72\x31\x0C\x30\x0A\x06\x03\x55\x04\x07\x0C\x03\x53\x46\x4F\x31\x0C\x30\x0A\x06\x03\x55\x04\x0A\x0C\x03\x4C\x42\x4C\x31\x11\x30\x0F\x06\x03\x55\x04\x03\x0C\x08\x52\x65\x69\x6E\x68\x61\x72\x64\x31\x1D\x30\x1B\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01\x16\x0E\x72\x67\x65\x6E\x74\x7A\x40\x6C\x62\x6C\x2E\x67\x6F\x76\x30\x1E\x17\x0D\x31\x38\x30\x36\x32\x31\x31\x39\x30\x35\x35\x34\x5A\x17\x0D\x31\x39\x30\x36\x32\x31\x31\x39\x30\x35\x35\x34\x5A\x30\x6C\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x44\x45\x31\x0F\x30\x0D\x06\x03\x55\x04\x08\x0C\x06\x52\x61\x69\x6E\x65\x72\x31\x0C\x30\x0A\x06\x03\x55\x04\x07\x0C\x03\x53\x46\x4F\x31\x0C\x30\x0A\x06\x03\x55\x04\x0A\x0C\x03\x4C\x42\x4C\x31\x11\x30\x0F\x06\x03\x55\x04\x03\x0C\x08\x52\x65\x69\x6E\x68\x61\x72\x64\x31\x1D\x30\x1B\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01\x16\x0E\x72\x67\x65\x6E\x74\x7A\x40\x6C\x62\x6C\x2E\x67\x6F\x76\x30\x82\x01\x22\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01\x0F\x00\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xAE\x0F\x28\x58\x78\xEC\xBE\xAB\x77\x4A\x09\x47\x75\x3A\x86\xFB\xF9\x1A\x32\x00\xD5\xCD\x0E\x27\x61\x9C\xCC\x66\xAC\x59\x47\xD6\xDB\x0B\x9E\x5A\x39\x74\x54\xA6\x0D\xDC\x0D\x8C\xEB\x05\xEE\xF7\x56\xDB\x90\xEB\x07\x03\x8F\x1B\xD0\x01\x2A\x56\xF6\x56\xE9\x3A\xC5\xD9\xAC\xE8\x47\x93\x3B\xF8\x05\x67\xEB\x92\xDA\x02\x87\xA2\xBE\x0D\xF1\xCA\x13\x0C\x67\xAA\x76\xCF\x88\x89\x6F\x23\xB5\x7F\x74\x0D\xD5\xFE\x06\x86\xA1\xF6\xAC\x76\x4A\x55\x74\x29\xDB\xE7\x61\x58\x61\x79\x64\x17\x33\xFF\x14\x10\xAE\xDD\x08\x67\xF5\xD3\x25\xE3\xC7\xFD\xD7\x0F\x67\x95\x34\x65\xC1\x1F\x3E\x05\x26\xED\xF4\xFB\x77\x20\xA5\x16\x9B\xE7\xAC\x9B\x6A\xA0\x24\x8A\x8F\x93\x55\x5D\x2D\xB4\x05\x67\xE4\x53\x4A\x02\x9D\xEB\xE1\x39\x9A\x1E\xE7\xB7\xE6\x6A\x2A\xEA\xEC\x8C\x01\xD7\x7F\x38\x55\x2E\x99\x7E\xF8\x2C\x6D\x9E\x10\x95\x69\xD9\x22\x67\xF2\x07\xD1\x6B\x3C\x51\xF2\x96\xD6\xAE\x67\x19\x57\xBC\x70\x6A\x5A\x6B\xAD\x45\x0B\x63\x07\x9E\x52\x2F\xC5\x43\xED\x8B\x8F\x0A\xA2\xBE\x02\xB0\x37\x07\x59\x7A\xCA\xB9\xEE\xED\xD2\xB2\x60\x59\xE2\x43\xB3\xAB\xA1\x37\x02\x03\x01\x00\x01\xA3\x50\x30\x4E\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14\xFB\x91\x23\xED\xAF\xB9\xEB\x4B\x42\xB4\xD4\x48\x96\xED\x15\x04\xE2\xB3\xA1\x09\x30\x1F\x06\x03\x55\x1D\x23\x04\x18\x30\x16\x80\x14\xFB\x91\x23\xED\xAF\xB9\xEB\x4B\x42\xB4\xD4\x48\x96\xED\x15\x04\xE2\xB3\xA1\x09\x30\x0C\x06\x03\x55\x1D\x13\x04\x05\x30\x03\x01\x01\xFF\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B\x05\x00\x03\x82\x01\x01\x00\x89\x99\x19\x10\x8A\x96\x7A\xB3\x25\xEE\xF1\x49\xBA\x0D\x4E\x98\x81\x79\xCE\xA6\x29\xE9\x0A\x12\xA5\x65\xD4\xC7\xF3\x7E\x24\x98\x91\x19\x15\x9C\xF1\x35\x11\x34\xC8\x0A\x4B\x8B\x40\xB0\xFC\x1E\xF0\xEA\xA0\x8D\x0F\x60\xCA\x3B\x7D\xD5\x2D\x69\xC3\xDE\xE0\xAA\x84\x8D\x4C\xF8\x17\xEC\x5F\xE2\x54\x0F\x55\x03\x71\x81\xA5\xE1\x9E\x35\xC2\xA9\x80\x12\x1C\x7F\x53\xE1\xAA\x52\x0E\xC5\xF6\x7C\x7C\xAE\xD9\xB4\x14\x9F\x10\xDD\x17\xE9\x7F\x2C\xF1\x65\xED\xBD\xAA\x26\x90\x96\xDB\xC1\x4A\x3F\x66\xB0\xB4\xDE\x49\x09\x1A\x94\x4E\x52\x2F\x59\x1C\x78\x84\xD0\x35\x17\xCA\x47\x45\x9F\x2C\x3D\x2A\x74\x4A\x8B\x6A\xAD\x66\x38\x9E\x89\x41\x65\xE9\x4C\x77\xB0\xD9\x2B\x8C\xD8\xD5\x55\x34\x1A\x49\x15\x19\xE8\x21\xB1\x76\x68\x3B\x04\x83\xCB\x00\x10\xCC\x0E\x4F\xEE\xFB\x72\x40\x2D\x84\xCF\x55\x8C\x46\xDE\x85\x4B\x49\x63\xD0\x27\x80\x94\xCD\x5B\xFD\x00\x47\x08\xB1\x4D\xCF\x8D\xE6\xE8\xC6\xD5\x7D\xDC\xB9\x17\x67\x1B\xC6\x85\xCA\xFA\xE5\x06\xF6\x13\x7A\xE6\x92\x55\xDE\xF7\xE3\x55\xBD\xB9\xBB\xD9\x0B\x09\x1C\x8C\x87\xEA\xF7\x44\x6D\xEC\xF3\x08";
# print x509_verify(chain, root);
 #print " verify chain";
# print x509_verify(cert_ref, "");
# print  x509_verify(cert_ref);
 #print "";
# print "cert ref";
 #print cert_ref;
 # print "F is", f;

}

event ssl_established(c: connection){
	print "SSL established", c;
}

event x509_ext_basic_constraints(f: fa_file, ext: X509::BasicConstraints){
#print "x509 test";
}

#event centraladdremote(ip: addr, reasonin: string, expire: time, as_response: string, as_request: string, tgt_request: string, tgt_response: string){
event centralautoadd(item: lbl){
	#if (ip in lbltable[(ip)]){
	#	print "already saw user";
	#}
	#else{
	print "Central added the following item to be allowed";
	print item;
	local ip= item$ip_src;
	print "IP added is";
	print ip;
	lbltable[(ip)] = lbl($ip_src=(ip));
	lbltable[(ip)] = item;
	#}
	#lbltable[(ip)]$as_res$status_code= 0;
	#lbltable[(ip)]$as_res$status= as_response;
	#lbltable[(ip)]$as_req$status_code= 0;
	#lbltable[(ip)]$as_req$status= as_request;
	#lbltable[(ip)]$tgt_res$status_code= 0;
	#lbltable[(ip)]$tgt_res$status= tgt_response;
	#lbltable[(ip)]$tgt_req$status_code= 0;
	#lbltable[(ip)]$tgt_req$status= tgt_request;
	#lbltable[(ip)]$tgt_req$status_code= 0;
	#lbltable[(ip)]$status= "ok";
	#lbltable[(ip)]$reason= reasonin;
	#lbltable[(ip)]$status_expires= expire;
	print lbltable[(ip)];
	Broker::send_event("bro/events/my_event", Broker::event_args(my_event4,lbltable[(ip)]));
}
event centraladdremote(ip: addr, reasonin: string, expire: time){
	#if (ip in lbltable[(ip)]){
	#	print "already saw user";
	#}
	#else{
	print "Central added the following ip";
	print ip;
	lbltable[(ip)] = lbl($ip_src=(ip));
	#}
	lbltable[(ip)]$as_res$status_code= 0;
	lbltable[(ip)]$as_res$status= "ok";
	lbltable[(ip)]$as_req$status_code= 0;
	lbltable[(ip)]$as_req$status= "Revoked";
	lbltable[(ip)]$tgt_res$status_code= 0;
	lbltable[(ip)]$tgt_res$status= "ok";
	lbltable[(ip)]$tgt_req$status_code= 0;
	lbltable[(ip)]$tgt_req$status= "ok";
	lbltable[(ip)]$tgt_req$status_code= 0;
	lbltable[(ip)]$status= "ok";
	lbltable[(ip)]$reason= reasonin;
	lbltable[(ip)]$status_expires= expire;
	print lbltable[(ip)];
	Broker::send_event("bro/events/my_event", Broker::event_args(my_event4,lbltable[(ip)]));

	

}
event centralremoveremote(ip: addr, reasonin: string, expire: time){
	#if (ip in lbltable[(ip)]){
	#	print "already saw user";
	#}
	#else{
	print "Central disabled the following ip";
	print ip;
	lbltable[(ip)] = lbl($ip_src=(ip));
	#}
	lbltable[(ip)]$as_res$status_code= -1;
	lbltable[(ip)]$as_res$status= "Revoked";
	lbltable[(ip)]$as_req$status_code= -1;
	lbltable[(ip)]$as_req$status= "Revoked";
	lbltable[(ip)]$tgt_res$status_code= -1;
	lbltable[(ip)]$tgt_res$status= "Revoked";
	lbltable[(ip)]$tgt_req$status_code= -1;
	lbltable[(ip)]$tgt_req$status= "Revoked";
	lbltable[(ip)]$tgt_req$status_code= -1;
	lbltable[(ip)]$status= "Revoked";
	lbltable[(ip)]$reason= reasonin;
	lbltable[(ip)]$status_expires= expire;
	print lbltable[(ip)];
	Broker::send_event("bro/events/my_event", Broker::event_args(my_event4,lbltable[(ip)]));

	

}

event krb_as_request(c: connection, msg: KRB::KDC_Request) &priority=-20
        {
# 	print " ";
	print "got as req";
		
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
	Broker::send_event("bro/events/my_event", Broker::event_args(my_event4,lbltable[(c$id$orig_h)]));
	
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

	Broker::send_event("bro/events/my_event", Broker::event_args(my_event4,lbltable[(c$id$orig_h)]));

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
	
	
        if (info?$server_cert){
                if(info$server_cert?$x509){
                lbltable[(c$id$orig_h)]$as_res$not_valid_before=info$server_cert$x509$certificate$not_valid_before;
                lbltable[(c$id$orig_h)]$as_res$not_valid_after=info$server_cert$x509$certificate$not_valid_after;
                lbltable[(c$id$orig_h)]$as_res$key_length=info$server_cert$x509$certificate$key_length;
                lbltable[(c$id$orig_h)]$as_res$serial=info$server_cert$x509$certificate$serial;
                lbltable[(c$id$orig_h)]$as_res$sig_alg=info$server_cert$x509$certificate$sig_alg;
                lbltable[(c$id$orig_h)]$as_res$issuer=info$server_cert$x509$certificate$subject;
                lbltable[(c$id$orig_h)]$as_res$status="ok";
                }
        }
        else{
        lbltable[(c$id$orig_h)]$as_res$status="CERT FAILED";
        lbltable[(c$id$orig_h)]$status="FAILED";
        lbltable[(c$id$orig_h)]$reason="as-res cert  FAILED";

        }
	
	
	lbltable[(c$id$orig_h)]$as_res$not_valid_before=info$server_cert$x509$certificate$not_valid_before;

#	Broker::send_print("bro/events/test", "AS result true");	
#	Broker::send_print("bro/events/test", "AS response OK from hostname " +addr_to_ptr_name(c$id$orig_h));	
	#print info;
	#print "";
	#print "now the connection info";
	#print c;
		Broker::send_event("bro/events/my_event", Broker::event_args(my_event4,lbltable[(c$id$orig_h)]));

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

		print "INFO";
	print info;
	print "INFO DONE";


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
        lbltable[(c$id$orig_h)]$status_expires=lbltable[(c$id$orig_h)]$as_req$not_valid_after;



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
	Broker::send_event("bro/events/my_event", Broker::event_args(my_event4,lbltable[(c$id$orig_h)]));







	print "tgs resp sucessful processed";
#	print info;
#	print "PRINT COMPLETE";

        }


 event bro_init(){
 print "startup";
 print "enableing broker";
 Broker::enable();
 Broker::subscribe_to_prints("bro/print/");
 Broker::subscribe_to_events("bro/central/");
 Broker::subscribe_to_events("bro/central");
 Broker::subscribe_to_events("bro/events/my_central");
 Broker::subscribe_to_events("bro/events/my_central/");
 Broker::listen(broker_port, "127.0.0.1");  #uncomment this to make bro the server
 #Broker::connect("127.0.0.1", broker_port, 1sec);
h = Broker::create_master("rabbitmaster");
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
        print "Broker::incoming_connection_established", peer_name;


	if (peer_name != "central" && peer_name!= "manualremover"){

        print "sending all current connections";
#        Broker::send_print("bro/events/test", "1");
#        Broker::send_print("bro/events/test", "myset");
#        Broker::send_print("bro/events/test", "myvec");
#	Broker::send_event("bro/events/my_event", Broker::event_args(my_event, "hi", 0));
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
	Broker::send_event("bro/events/my_event", Broker::event_args(my_event4,lbltable[t]));
	print lbltable[t];
}
#	Broker::send_event("bro/events/my_event", Broker::event_args(my_event4,lbltable[to_addr("192.168.2.1")]));
#	Broker::send_event("bro/events/my_event", Broker::event_args(my_event2,mytest2));
	
}
else{
print "central connected, waiting for adds";
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



function delayedkeycheck(ip: addr) : count
      {
      # This delays until condition becomes true.
      }


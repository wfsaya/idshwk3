global ip_ua :table[addr] of set[string];

event http_header(c: connection,is_orig: bool, name: string, value: string)
    {
	local ip :addr = c$id$orig_h;
	if(name=="USER-AGENT")
	    {
	    if(ip !in ip_ua)
                ip_ua[ip]=set(to_lower(value));
	    else
	        add ip_ua[ip][to_lower(value)];
	    }
	}

event zeek_done()
	{
	for(ip in ip_ua)
	    {
	    if(|ip_ua[ip]|>=3)
	        print fmt("%s is a proxy",ip);
	    }
	}
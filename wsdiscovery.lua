local wsdiscovery = Proto("wsd", "Web Service Discovery")

function wsdiscovery.dissector(buffer, pinfo, tree)
    tree:add(wsdiscovery,buffer())
    
    local soapString = buffer():string(ENC_UTF_8)
    local action = soapString:match("<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/(.*)</wsa:Action>")

    pinfo.cols.protocol = "WS-Discovery"
    pinfo.cols.info:set("WS-Discovery: "..action)
    
    Dissector.get("xml"):call(buffer,pinfo,tree)
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(3702, wsdiscovery)
rule mal_CyberStealer {
    meta:
        description = "Detects Cyber Stealer malware"
        author = "Muhammad Hasan Ali @muha2xmad"
        date = "29-07-2025"
    strings:
            $str1 = "Newtonsoft.Json.dll" fullword wide
            $str2 = "time_keylogs" fullword wide
            $str3 = "time_screenshot" fullword wide
            $str4 = "&username=cyber65" fullword wide
            $str5 = "/heartbeat.php?hwid=" wide
            $str6 = "DNSManager/1.0" fullword wide
            
            $cc1 = "https://pastebin.com/raw/6K66Aeyr" fullword wide
            $cc2 = "https://paxrobot.digital/webpanel/" fullword wide


        
    condition:
        uint16(0) == 0x5a4d 
        and  (
            5 of them 
            or 1 of ($cc*) )
        
}







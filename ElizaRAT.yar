rule mal_ElizaRAT {
    meta:
        description = "Detects ElizaRAT malware"
        author = "Muhammad Hasan Ali @muha2xmad"
        date = "30-07-2025"
    strings:
            $str1 = "1Gwy3yPyyYJVoOvCMfsmhhCknC-tiuNFv" fullword wide
            $str2 = "BaseFilteringEngine" fullword wide
            $str3 = "xijinping@round-catfish-416409.iam.gserviceaccount.com" fullword wide
            
            $xstr1 = "notasecret" fullword wide
            $xstr2 = "you request has been performed against Transfer" fullword wide
            $xstr3 = "Folder ID: " fullword wide

           
    condition:
        uint16(0) == 0x5a4d 
        and (
            2 of ($xstr*)
            or  1 of ($str*) 
        )
}

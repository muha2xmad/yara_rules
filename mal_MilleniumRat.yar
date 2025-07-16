rule mal_MilleniumRat {
    meta:
        description = "Detects MilleniumRat malware"
        author = "Muhammad Hasan Ali @muha2xmad"
        date = "2025-06-29"
    strings:
            $str1 = "https://raw.githubusercontent.com/attatier/Cloud/main/MilInfo.txt" fullword wide
            $str2 = "GoogleChromeUpdateLog" fullword wide
            $str3 = "SoftwareLogs" fullword wide
            $str4 = "ChromeUpdateCash" fullword wide
            $str5 = "play MP3" fullword wide
            $str6 = "extractorhelp - help" fullword wide
            $str7 = "displayrotation" fullword wide


        
    condition:
        uint16(0) == 0x5a4d and  6 of ($str*) 
}

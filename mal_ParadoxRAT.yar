rule mal_ParadoxRAT {
    meta:
        description = "Detects ParadoxRAT malware"
        author = "Muhammad Hasan Ali @muha2xmad"
        date = "2025-06-12"
        hash1 = "13e9042f6fa0c525b1cbe97d3273b1c0ae0b63e426ffaeec7caa3e11786141f2"
    strings:
            $str1 = "ParadoxRAT" fullword ascii
            $str2 = "C:\\Users\\Jordan\\Desktop\\Paradox Coding\\ParadoxRAT Client\\ParadoxRAT Client\\obj\\x86\\Release\\ParadoxRAT Client.pdb" fullword ascii
            $str3 = "ParadoxRAT_Client" ascii
            $str4 = "FF_Needs" ascii
            $str5 = "bgFlood" ascii
            $str6 = "bgFlood_DoWork" ascii


        
    condition:
        uint16(0) == 0x5a4d and  4 of ($str*) 
}
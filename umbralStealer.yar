rule mal_UmbralStealer {
    meta:
        description = "Detects Umbral Stealer malware"
        author = "Muhammad Hasan Ali @muha2xmad"
        date = "17-07-2025"
    strings:
            $str1 = "computersystem get totalphysicalmemory" fullword wide
            $str2 = "os get Caption" fullword wide
            $str3 = "Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER" fullword wide
            $str4 = "path win32_VideoController get name" fullword wide
            $str5 = "Umbral Stealer" wide
            $str6 = "https://github.com/Blank-c/Umbral-Stealer" fullword wide
            $str7 = "Opera/9.80 (Windows NT 6.1; YB/4.0.0) Presto/2.12.388 Version/12.17" fullword wide
            $str8 = "_\\|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items\\.\\|_[A-Z0-9]+" fullword wide


        
    condition:
        uint16(0) == 0x5a4d and  (6 of ($str*) )
        
}


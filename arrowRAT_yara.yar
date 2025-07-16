rule mal_ArrowRAT {
    meta:
        description = "Detects ArrowRAT Malware"
        author = "Muhammd Hasan Ali @muha2xmad"
        date = "12-07-2025"

    
    strings:       
        // base64 encoded Software\Microsoft\Windows NT\CurrentVersion\Winlogon\    
        $b64_reg1 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcQ3VycmVudFZlcnNpb25cV2lubG9nb25c" fullword wide
        // base64 encoded Software\Microsoft\Windows NT\CurrentVersion\Winlogon
        $b64_reg2 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcQ3VycmVudFZlcnNpb25cV2lubG9nb24=" fullword wide
        $str1 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\cvtres.exe" fullword wide
        $str2 = "TMP_Cookiesex" fullword wide
        $str3 = "C:\\Windows\\System32\\ComputerDefaults.exe" wide fullword
        $str4 = "Software\\Classes\\ms-settings\\shell\\open\\command" wide fullword
        $str5 = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command Add-MpPreference -ExclusionPath '" fullword wide
        $str6 = "CqbkTHriRRbQjaArtJfF" fullword wide


    condition:
        uint16(0) == 0x5a4d and (1 of ($b64_reg*)) and (4 of ($str*))
}

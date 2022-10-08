rule WannaCry_Ransomware {

    meta:
        author = "maT"
        description = "Detects the WannaCry dropper + encryptor + decryptor"
        filetype = "PE"
        version = "1.0"
        reference = "https://academy.tcm-sec.com/courses/enrolled/1547503"
        hash_dropper = "24D004A104D4D54034DBCFFC2A4B19A11F39008A575AA614EA04703480B1022C"
        hash_encryptor = "ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA"
        hash_decryptor = "B9C5D4339809E0AD9A00D4D3DD26FDF44A32819A54ABF846BB9B560D81391C25"

    strings:
        $s1 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
        $s2 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" fullword ascii
        $s3 = "WNcry@2ol7" fullword ascii
        $s4 = "taskse.exe" fullword ascii
        $s5 = "tasksche.exe" fullword ascii
        $s6 = "taskdl.exe" fullword ascii
        $s7 = "msg/m_portuguese.wnry" fullword ascii
        $s8 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii
        $s9 = "vssadmin delete shadows" fullword ascii
        
        $s10 = "WanaCrypt0r" fullword wide
        $s11 = "Ooops, your files have been encrypted!" fullword wide
        $s12 = "@WanaDecryptor@.bmp" fullword wide
        
    condition:
        uint16(0) == 0x5A4D // MZ
        and 4 of ($s*)
        and filesize < 4MB
}


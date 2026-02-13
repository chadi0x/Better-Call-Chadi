rule Webshell_PHP_Generic {
    meta:
        description = "Detects common PHP webshell patterns (WSO, C99, etc.)"
        severity = "High"
    strings:
        $s1 = "eval(base64_decode(" nocase
        $s2 = "system($_GET[" nocase
        $s3 = "passthru($_POST[" nocase
        $s4 = "shell_exec(" nocase
        $s5 = "FilesMan" nocase
        $s6 = "c99shell" nocase
        $s7 = "phpspy" nocase
    condition:
        any of them
}

rule Mimikatz_Memory_Indicator {
    meta:
        description = "Detects Strings associated with Mimikatz credentials dumper"
        severity = "Critical"
    strings:
        $s1 = "gentilkiwi" wide ascii
        $s2 = "mimikatz" wide ascii
        $s3 = "sekurlsa" wide ascii
        $s4 = "logonPasswords" wide ascii
        $s5 = "lsadump" wide ascii
    condition:
        any of them
}

rule Suspicious_Powershell_Encoded {
    meta:
        description = "Detects encoded PowerShell commands commonly used by droppers"
        severity = "Medium"
    strings:
        $s1 = "powershell -enc" nocase
        $s2 = "powershell.exe -EncodedCommand" nocase
        $s3 = "powershell -nop -w hidden" nocase
        $s4 = "IEX ((new-object net.webclient).downloadstring" nocase
    condition:
        any of them
}

rule CobaltStrike_Beacon_Indicator {
    meta:
        description = "Detects potential Cobalt Strike Beacon artifacts"
        severity = "Critical"
    strings:
        // Common Beacon C2 default strings or config structures
        $s1 = "%02d/%02d/%02d %02d:%02d:%02d" ascii // Beacon date format
        $s2 = "Started service %s on %s" ascii      // Beacon service start
        $s3 = "I am a beacon" wide ascii            // Joke/Test string often left in cracks
        $s4 = "/C %s" ascii                         // Command execution
        $s5 = "ReflectiveLoader" ascii              // Standard artifact
    condition:
        2 of them
}

rule Ransomware_WannaCry_Strings {
    meta:
        description = "Detects strings associated with WannaCry Ransomware"
        severity = "Critical"
    strings:
        $s1 = "WanaCrypt0r" wide ascii
        $s2 = "wnry" wide ascii
        $s3 = "msg/m_bulgarian.wnry" ascii
        $s4 = "tasksche.exe" ascii
        $s5 = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii // Killswitch (variant 1)
    condition:
        any of them
}

rule Emotet_Payload_Strings {
    meta:
        description = "Detects strings associated with Emotet/Geodo payloads"
        severity = "High"
    strings:
        $s1 = "E:\\my_work\\8_11_2019\\loader\\Release\\loader.pdb" ascii
        $s2 = "cookie: " ascii
        $s3 = "user-agent: " ascii
        $s4 = "content-type: application/x-www-form-urlencoded" ascii
    condition:
        all of them
}

rule Test_Signature_EVIL {
    meta:
        description = "DEBUG: Test rule to verify YARA is working"
        severity = "Low"
    strings:
        $s1 = "EVIL_TEST_STRING"
    condition:
        $s1
}

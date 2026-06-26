rule Basic_Malware_Detection
{
    meta:
        description = "Detects basic malware keywords"

    strings:
        $a = "malware" nocase
        $b = "trojan" nocase
        $c = "hack" nocase

    condition:
        any of them
}

rule Advanced_Malware_Detection
{
    meta:
        description = "Detects advanced attack behavior"

    strings:
        $x = "malicious" nocase
        $y = "attack" nocase
        $z = "unauthorized access" nocase

    condition:
        any of them
}

rule URL_Detection
{
    meta:
        description = "Detects URLs (phishing/malicious links)"

    strings:
        $url = /http:\/\/[a-zA-Z0-9\.]+/

    condition:
        $url
}

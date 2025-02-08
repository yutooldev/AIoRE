rule get_file_string {
    // 匹配由3个以上可见字符组成,且由不可见字符开头和结尾的字符串
    strings:
        $visible_ascii = /[\x00-1F]{1}[ -~]{3,}[\x00-1F]{1}/

    condition:
        $visible_ascii
}
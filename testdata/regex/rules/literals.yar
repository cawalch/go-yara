rule re_literals {
  strings:
    $a = /abc/
    $b = /a\.c/
  condition:
    any of them
}


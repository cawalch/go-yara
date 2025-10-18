rule re_classes {
  strings:
    $a = /[a-c]x[0-9]/
    $b = /[^0-9]/
  condition:
    any of them
}


rule re_quantifiers {
  strings:
    $a = /a{2,4}b/
    $b = /c+?d/
    $c = /e*?f/
  condition:
    any of them
}


rule re_alternation {
  strings:
    $a = /(foo|bar)/
  condition:
    $a
}


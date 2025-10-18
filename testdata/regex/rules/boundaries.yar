rule re_boundaries {
  strings:
    $a = /\babc\b/
    $b = /\Babc\B/
  condition:
    any of them
}


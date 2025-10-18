rule re_anchors {
  strings:
    $a = /^abc$/
  condition:
    $a
}


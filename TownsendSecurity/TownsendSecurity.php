<?php

namespace TownsendSecurity;

require_once __DIR__ . '/lib/AuthFile.php';
require_once __DIR__ . '/lib/EncryptionService.php';
require_once __DIR__ . '/lib/KeyServer.php';
require_once __DIR__ . '/lib/KeyService.php';


abstract class Service {

  public $key_servers = array();

  public function __construct() {
  }

}

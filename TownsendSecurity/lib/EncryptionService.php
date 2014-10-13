<?php

namespace TownsendSecurity;

class EncryptionService extends Service {

  public function __construct() {
    parent::__construct();
  }

  public function addKeyServer($server, $port, $ca_cert_file, $client_cert_key_file) {
    $key_server = new KeyServer($server, $port, $ca_cert_file, $client_cert_key_file);
    array_push($this->key_servers, $key_server);
  }

  public function encrypt($text = '', $key = '', $op = 'encrypt', $options = array()) {
    $servers = $this->key_servers;

    while (!empty($servers)) {
      $server = array_pop($servers);
      $connection = $server->connect();
      if (isset($connection)) {
        $data = $server->encrypt($connection, $text, $key, $op, $options);
        if (!empty($data)) {
          return $data;
        }
      }
    }
  }

}

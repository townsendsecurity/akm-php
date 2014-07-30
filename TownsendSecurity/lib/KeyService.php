<?php

namespace TownsendSecurity;

class KeyService extends Service {

  public function __construct() {
    parent::__construct();
  }

  public function addKeyServer($server, $port, $ca_cert_file, $client_cert_key_file) {
    $key_server = new KeyServer($server, $port, $ca_cert_file, $client_cert_key_file);
    array_push($this->key_servers, $key_server);
  }

  public function getSymmetricKey($name = '', $instance = '', $format = 'BIN') {
    $key = '';

    // Define a temporary array for working with servers.
    $servers = $this->key_servers;

    while (empty($key) && !empty($servers)) {
      $server = array_pop($servers);
      $connection = $server->connect();
      if (isset($connection)) {
        $key = $server->getServerSymmetricKey($connection, $name, $instance, $format);
      }      
    }

    if (!empty($key)) {
      return $key;
    }
  }

}

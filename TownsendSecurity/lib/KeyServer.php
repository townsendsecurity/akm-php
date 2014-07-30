<?php

namespace TownsendSecurity;

use TownsendSecurity\AuthFile;

class KeyServer {

  protected $key_server;
  protected $server_port;
  protected $cafile;
  protected $local_cert;
  protected $connection;

  public function __construct($key_server, $server_port, $cafile, $local_cert) {
    $this->key_server   = $key_server;
    $this->server_port = $server_port;
    $this->cafile       = new AuthFile($cafile);
    $this->local_cert   = new AuthFile($local_cert);
  }

  public function connect() {
    // Define the options for the TLS context.
    $options = array(
      'ssl' => array(
        'cafile' => $this->cafile->auth_file,
        'capture_peer_cert' => TRUE,
        'local_cert' => $this->local_cert->auth_file,
        'verify_peer' => TRUE,
      ),
    );

    // Create the TLS context.
    $context = stream_context_create($options);

    // Create the connection to the key server.
    $host = $this->key_server . ':' . $this->server_port;
    $this->connection = stream_socket_client('tls://' . $host, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);

    return $this->connection;
  }

  public function getServerSymmetricKey($connection = '', $name = '', $instance = '', $format = 'BIN') {
    $key = '';

    if ($connection) {
      $request = sprintf("000712001%-40s%24s" . $format, $name, '');
      fwrite($connection, $request);
      $len = fread($connection, 5);
      if ($len) {
        $response = fread($connection, $len + 1);
        if ($response) {
          $key = substr($response, 95);
        }
      }
    }

    if (!empty($key)) {
      return $key;
    }
  }

}

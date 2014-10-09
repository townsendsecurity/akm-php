<?php

namespace TownsendSecurity;

use TownsendSecurity\AuthFile;

function rand_string($nchars = 16) {
  $allowed = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

  $len = strlen($allowed) - 1;

  $s = '';

  for ($i = 0; $i != $len; ++$i) {
    $index = rand(0, $len);
    $s .= $allowed[$index];
  }

  return $s;
}

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

  public function encrypt($connection, $text = '', $key = '', $op = 'encrypt', $options = array()) {
    if ($op == 'encrypt') {
      // key length = 40 (left justify pad on right)
      // instance = 24 (leave blank or instance got back)

      // generate random iv to use w/ encryption
      $iv = rand_string(16);
      $textcount = sprintf('%05d', strlen($text));
      if (floor($textcount / 16) != $textcount / 16) {
        $padlen = 16 * ceil($textcount / 16);
        $text = sprintf('% -' . $padlen . 's', $text);
        $textcount = sprintf('%05d', strlen($text));
      }
      $key = sprintf('% -64s', $key);
      $request = sprintf('000982019YNB16' . $textcount . 'YNYY' . $iv . '' . $key . '' . '' . $text . '');
      fwrite($connection, $request);
      $len = fread($connection, 5);
      if ($len) {
        $return = fread($connection, $len + (3 * $textcount));
        if ($return) {
          $inst = substr($return, 15, 24);
          $coded = substr($return, 39);
          $value = $iv . $inst . $coded;
        }
      }
      else {
        return '';
      }
      fclose($connection);
      return $value;
    }
    else {
      $iv = substr($text, 0, 16);
      $inst = substr($text, 16, 24);
      $coded = substr($text, 40);
      $textcount = sprintf('%05d', strlen($coded));
      $keypad = sprintf('% -40s', $key);
      $key = $keypad . $inst;
      if (floor($textcount / 16) != $textcount / 16) {
        $pandlen = 16 * ceil($textcount / 16);
        $coded = sprintf('% -' . $padlen . 's', $coded);
        $textcount = sprintf('%05d', strlen($coded));
      }
      $decrypt_header = '001012021YNB16' . $textcount . 'BINYNYY' . $iv . $key;
      $decrypt = sprintf($decrypt_header . $coded);
      fwrite($connection, $decrypt);
      $len = fread($connection, 5);
      if ($len) {
        $rsp = fread($connection, $len + $textcount);
        if ($rsp) {
          $value = substr($rsp, 39);
          $value = rtrim($value);
        }
      }
      else {
        return '';
      }
      fclose($connection);
      return $value;
    }
  }

}

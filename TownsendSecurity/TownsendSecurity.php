<?php

namespace TownsendSecurity;

spl_autoload_register(function($class) {
  // `$class' comes in as fully qualified with namespaces
  $parts = explode('\\', $class);
  require_once __DIR__ . '/lib/' . end($parts) . '.php';
});

abstract class Service {

  public $key_servers = array();

  public function __construct() {
  }

}

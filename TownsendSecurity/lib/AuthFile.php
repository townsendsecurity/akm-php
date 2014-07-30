<?php

namespace TownsendSecurity;

class AuthFile {

  public $auth_file;

  public function __construct($auth_file) {
    $this->auth_file = $auth_file;
  }

  public function isReadable() {
    if (is_readable($this->auth_file)) {
      return TRUE;
    }
    else {
      return FALSE;
    } 
  }

}

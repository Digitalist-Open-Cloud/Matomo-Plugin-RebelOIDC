<?php

/**
 * Bootstrap for running the pure unit tests outside Matomo (no Matomo classes
 * available). CI runs the tests via the Matomo test harness instead.
 */

spl_autoload_register(function ($class) {
    $prefix = 'Piwik\\Plugins\\RebelOIDC\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $file = dirname(__DIR__) . '/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require_once $file;
    }
});

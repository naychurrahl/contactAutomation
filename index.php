<?php

error_reporting(E_ALL);
ini_set('display_errors', 1); // 0 in prod
ini_set('log_errors', 1);

header("Access-Control-Allow-Headers: Content-Type, Authorization");
header('Content-Type: application/json');
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
  http_response_code(204); // No content
  exit();
}

require_once __DIR__ . '/Controller.php';

// Get method and URI

$method = $_SERVER['REQUEST_METHOD'] ?? "GET";

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? "null";

$uri = trim($uri, '/');


// Break URI parts

$parts = explode('/', $uri);

$controller = new Controller($parts, $method);

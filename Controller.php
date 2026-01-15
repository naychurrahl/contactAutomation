<?php

require_once __DIR__ . '/Functions.php';

class Controller
{

  private $functions;

  private $method;

  private $requestBody;

  private $route;

  public function __construct($path, $method)
  {

    $this->route  = $path[0] ?? null;

    $this->method = $method;

    $this->functions = new Functions();

    switch (True) {
      case ! empty($_POST)  & $this->method === 'POST':
        $this->requestBody = $_POST;
        break;

      case ! empty($_GET) & $this->method === 'GET':
        $this->requestBody = $_GET;
        break;

      default:
        $this->requestBody = (array) json_decode(file_get_contents("php://input"), true);
    }

    $this->handle();
  }

  private function handle()
  {
    switch ($this->route) {
      case '':
      case '/':
        switch ($this->method) {
          case 'POST':
            return "null";
          case 'GET':
            //return $this->functions->patchLogin($this->parom);
            return "GET";
          default:
            return $this->methodNotAllowed();
        }
        break;

      case 'ping':
        $this -> functions -> ping();

      default:
        return $this->endpointNotFound();
    }
  }

  private function methodNotAllowed(array $allowed = ["POST", "GET"])
  {
    http_response_code(405);
    header('Allow: ' . implode(', ', $allowed));
    echo json_encode([
      'error' => 'Method Not Allowed',
      'allowed' => $allowed
    ]);
  }

  private function endpointNotFound(array $allowed = ["/"])
  {

    $res = [
      "header" => 'HTTP/1.1 404 Endpoint Not Found',
      "rescode" => 404,
      "message" => [
        'Message' => 'endpoint not found',
        'Allowed' => implode(', ', $allowed),
      ],
    ];

    header($res['header']);
    http_response_code($res['rescode']);

    echo json_encode($res['message']);
  }
}

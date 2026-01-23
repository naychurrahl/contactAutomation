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
    switch (strtolower($this->route)) {
      case '':
      case '/': //login
        if ($this->method !== 'GET') $this->methodNotAllowed(['GET']);

        $this -> functions -> buildLink();
        break;

      case "callback": //onboarding
        if ($this -> method !== 'GET') $this -> methodNotAllowed(['GET']);

        if (! empty($this->requestBody['code']) && ! empty($this->requestBody['state'])) {
          //session_start();

          $state = $this->requestBody['state'];

          $newState = $_COOKIE['state'] ?? null;

          if ($state !== $newState) {
            header("HTTP/1.1 400 Missing or invalid state");

            http_response_code(400);

            die(json_encode(["Error"=> 'Missing or invalid state.']));
          }

          setcookie(
            "state",
            "state",
            [
              'expires' => time() - (600), // 7 days
              'path' => '/',
              //'domain' => 'localhost', // optional, your domain
              'secure' => true, // only HTTPS
              'httponly' => true, // not accessible to JS
              'samesite' => 'none' // prevent CSRF
            ]
          );
          
          $this -> functions -> logIn($this->requestBody['code']);
        }
        
        die(json_encode('no state'));
        break;

      case "logout":

        $this -> functions -> logOut();
        break;
      case "ping": //Ping
        $this->functions->ping($this -> method);

      default: //Main
        if ($this->method !== 'POST') $this->methodNotAllowed(['POST']);
        
        //The route is the form owner's user ID
        $this->functions->contactPayloadBuilder($this->requestBody, strtolower($this -> route));

      /*
      Endpoints: 
      login \GET 
      Main \POST  ✔️
      Callback \GET  ✔️
      Ping \*  ✔️
       */
    }
  }

  private function methodNotAllowed(array $allowed = ["POST", "GET"])
  {
    http_response_code(405);
    header('Allow: ' . implode(', ', $allowed));
    die (json_encode([
      'error' => 'Method Not Allowed',
      'allowed' => implode(', ', $allowed)
    ]));
  }

  private function endpointNotFound(array $allowed = ['/', '/callback', '/ping'])
  {

    header("HTTP/1.1 404 EndPoint Not Found");

    http_response_code(404);

    die (json_encode([
      'Message' => 'EndPoint Not Found',
      'Allowed' => $allowed,
    ]));
  }
}

/*
End points go:
://domain/userid -> Main aka form handler
://domain/ -> Login aka build link aka part 1 of oauth
://domain/callback -> Onboarding aka part 2 of oauth



Contact saving routine:
End user fills form,
Clicks submit,
Form data sent to ://domain/userid via POST,

-inBackend:
Check if request method is POST,
if not, return 405 Method Not Allowed,
if True, call contactPayloadBuilder with request body and userid (from route),

--In contactPayloadBuilder:
Check if userid is valid by looking up file,
if not, return 404 EndPoint Not Found,
if true, check that form at leasst has a valid phone number
if not, return 400 Bad Request,
if true, fetch name and email. Default to null,
build payload,
call Main with json encoded payload

--In Main:
Load token for userid,
if not found, return 404 Token Not Found,
Call endpoint and sign with token,
Return Success, Fail or Error!.

Finito!



Login sequence:
End user visits ://domain/  Basically root,
check if request method is GET,
if not, return 405 Method Not Allowed,
Call buildLink,

--In buildLink:
Add state param,
Build URL,
returns link to frontend,

Finito!


Login callback sequence:
End user is redirected back to ://domain/callback?code=xxxx&state=yyyy,
check if request method is GET,
if not, Do nothing,
If code in request body, call logIn with code,

--In logIn:
prepare payload
Get tokens from endpoint,
If fail, return Error!,
If success, generate secret key,
Save tokens and secret key to file,
set cookies with id and secret key in jwt,
redirect to dashboard,

Finito!



openssl req -newkey rsa:2048 -nodes -keyout localhost.key -x509 -days 365 -out localhost.crt -subj "/C=US/ST=NA/L=NA/O=Dev/OU=Dev/CN=localhost" && php -S localhost:5600 index.php -d "openssl.local_cert=localhost.crt" -d "openssl.local_pk=localhost.key"



openssl req -newkey rsa:2048 -nodes -keyout localhost.key -x509 -days 365 -out localhost.crt -subj "/C=US/ST=NA/L=NA/O=Dev/OU=Dev/CN=localhost"

*/
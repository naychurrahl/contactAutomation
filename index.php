<?php

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

function sendCurlRequest(string $url, string $method = "GET", array $headers = [], array | string  | null $body = null): string | array
{
  $ch = curl_init();

  // Set URL
  curl_setopt($ch, CURLOPT_URL, $url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

  // Set method
  curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));

  // Set headers if provided
  if (!empty($headers)) {
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
  }

  // Set body if provided
  if ($body !== null) {

    if (is_array($body)) {
      $body = http_build_query($body);
    }
    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
  }

  // Execute request
  $response = curl_exec($ch);
  $error = curl_error($ch);
  $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);

  //curl_close($ch);

  if ($error) {
    return ["error" => $error];
  }

  return [
    "status" => $status,
    "response" => $response
  ];
}

function loadToken(): string | null
{
  $tokenPath = 'token.json';
  if (file_exists($tokenPath)) {
    $tokenData = json_decode(file_get_contents($tokenPath), true);

    if (isset($tokenData['expires_at']) && $tokenData['expires_at'] < time()) {
      // Token has expired
      return refreshToken();
    }

    return $tokenData['access_token'];
  }
  return null;
}

function refreshToken(): string | null
{
  $newToken = sendCurlRequest(
    "https://oauth2.googleapis.com/token",
    "POST",
    ["Content-Type" => "application/x-www-form-urlencoded"],
    [
      "client_id" => "300953082028-bii3s0khdqbpdcro1mlihp67j73tr14c.apps.googleusercontent.com",
      "client_secret" => "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",
      "refresh_token" => "1//030-Tdogihi4oCgYIARAAGAMSNwF-L9IrUGjwMd7ji8c_nzGr-sNIJsiH42YAjK9CtiDg3-3ELyXEyfteLBfTN9o-_hR1Z3184ZU",
      "grant_type" => "refresh_token"
    ]
  );

  if (isset($newToken['error'])) {
    return $newToken['error'];
  }

  $tokenResponse = json_decode($newToken['response'], true);
  print_r($tokenResponse);
  $accessToken = $tokenResponse['access_token'];
  $expiresIn = $tokenResponse['expires_in'];
  $expiresAt = time() + $expiresIn;

  // Save new token data
  $tokenData = [
    "access_token" => $accessToken,
    "refresh_token" => "1//030-Tdogihi4oCgYIARAAGAMSNwF-L9IrUGjwMd7ji8c_nzGr-sNIJsiH42YAjK9CtiDg3-3ELyXEyfteLBfTN9o-_hR1Z3184ZU",
    "expires_at" => $expiresAt
  ];

  file_put_contents('token.json', json_encode($tokenData));

  return $accessToken;
}

function validatePhoneNumber(string $phone): bool | string
{
  // Remove common separators
  $clean = preg_replace('/[\s\-\(\)\.]/', '', $phone);

  // Must start with optional + followed by digits only
  if (!preg_match('/^\+?[0-9]{7,15}$/', $clean)) {
    return false;
  }

  return $clean;
}

function main(string $phone, string | null $name = null, string | null $email = null): array | null
{
  //Clean name
  $name = trim($name . " Customer");

  // Load token
  $token = loadToken();
  if (!$token) {
    echo json_encode("Failed to load or refresh token.");
    return null;
  }

  // Prepare contact payload
  $contactPayload = json_encode([
    "names" => [
      ["displayName" => "Customer", "familyName" => $name]
    ],
    "phoneNumbers" => [
      ["value" => $phone]
    ],
  ]);

  if ($email) {
    $contactPayload["emailAddresses"] = [
      ["value" => $email]
    ];
  }

  echo json_encode($contactPayload);
  return null;
  $response = sendCurlRequest(
    "https://people.googleapis.com/v1/people:createContact",
    "POST",
    [
      "Authorization: Bearer " . $token,
      "Content-Type: application/json"
    ],
    $contactPayload
  );

  if (isset($response['error'])) {
    echo json_encode("Error: " . $response['error']);
  } else {
    echo json_encode($response['status'] == 200 ? "Success" : "Failed");
  }

  return $response;
}

switch ($_SERVER['REQUEST_METHOD']) {
  case 'OPTIONS':
    // Handle preflight request
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    exit(0);

  case 'POST':
    # code...
    if (empty($_POST)) {
      $_POST = (array) json_decode(file_get_contents("php://input"), true);
    }

    /* $_POST = [
      "phone" => "+1234567898",
      "name" => "Lois Doe",
      //"email" => "john.doe@example.com"
    ]; */

    if (isset($_POST['phone'])) {

      if ($phoneNumber = validatePhoneNumber($_POST['phone'])) {

        $name = $_POST['name'] ?? null;
        $email = $_POST['email'] ?? null;

        //echo refreshToken();
        main($phoneNumber, $name, $email);
      } else {
        echo json_encode("invalid phone number");
      }
    } else {

      echo json_encode("Phone number is required.");
    }
    break;

  default:
    # code...
    http_response_code(405);
    die(json_encode("Method not allowed: Use POST"));
}

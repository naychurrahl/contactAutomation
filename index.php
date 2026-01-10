<?php

error_reporting(null);

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

define('CONFIG_PATH', __DIR__ . '/../config/');
define('SECRET', CONFIG_PATH . 'honeypot');
define('TOKEN_PATH', CONFIG_PATH . 'token');

if (!file_exists(CONFIG_PATH . 'keys.json')) {
  die(json_encode("Missing keys.json in config directory."));
}

define('KEY', json_decode(file_get_contents(CONFIG_PATH . 'keys.json'), true));

define('SALT_LENGTH', 16);
define('IV_LENGTH', 12);
define('TAG_LENGTH', 16);
define('PBKDF2_ITERATIONS', 100000);
define('KEY_LENGTH', 32);

function encryptSecret(string $plaintext, string $passphrase = KEY['keys']): string
{

  $salt = random_bytes(SALT_LENGTH);
  $iv   = random_bytes(IV_LENGTH);

  $key = hash_pbkdf2(
    'sha256',
    $passphrase,
    $salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    true
  );

  $tag = '';
  $ciphertext = openssl_encrypt(
    $plaintext,
    'aes-256-gcm',
    $key,
    OPENSSL_RAW_DATA,
    $iv,
    $tag,
    '',
    TAG_LENGTH
  );

  if ($ciphertext === false) {
    throw new RuntimeException('Encryption failed');
  }

  return base64_encode($salt . $iv . $tag . $ciphertext);
}

function decryptSecret(string $encryptedBase64, string $passphrase = KEY['keys']): string
{

  $data = base64_decode($encryptedBase64, true);

  if ($data === false) {
    throw new InvalidArgumentException('Invalid base64 input');
  }

  $offset = 0;

  $salt = substr($data, $offset, SALT_LENGTH);
  $offset += SALT_LENGTH;

  $iv = substr($data, $offset, IV_LENGTH);
  $offset += IV_LENGTH;

  $tag = substr($data, $offset, TAG_LENGTH);
  $offset += TAG_LENGTH;

  $ciphertext = substr($data, $offset);

  $key = hash_pbkdf2(
    'sha256',
    $passphrase,
    $salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    true
  );

  $plaintext = openssl_decrypt(
    $ciphertext,
    'aes-256-gcm',
    $key,
    OPENSSL_RAW_DATA,
    $iv,
    $tag
  );

  if ($plaintext === false) {
    throw new RuntimeException('Decryption failed or data tampered');
  }

  return $plaintext;
}

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

  if (file_exists(TOKEN_PATH)) {
    $tokenData = json_decode(decryptSecret(file_get_contents(TOKEN_PATH), KEY['token']), true);

    if (isset($tokenData['expires_at']) && $tokenData['expires_at'] < time()) {
      // Token has expired
      return refreshToken();
    }

    return $tokenData['access_token'];
  }

  return refreshToken();
}

function refreshToken(): string | null
{
  define('SECRETS', json_decode(decryptSecret(file_get_contents(SECRET)), true));

  $newToken = sendCurlRequest(
    "https://oauth2.googleapis.com/token",
    "POST",
    ["Content-Type" => "application/x-www-form-urlencoded"],
    SECRETS,
  );

  if (isset($newToken['error'])) {

    return $newToken['error'];
  }

  $tokenResponse = json_decode($newToken['response'], true);

  $accessToken = $tokenResponse['access_token'];
  $expiresIn = $tokenResponse['expires_in'];
  $expiresAt = time() + $expiresIn;

  // Save new token data
  $tokenData = [

    "access_token" => $accessToken,
    "expires_at" => $expiresAt

  ];

  file_put_contents(TOKEN_PATH, encryptSecret(json_encode($tokenData), KEY['token']));

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

function main(string $phone, string | null $name = null, string | null $email = null): void
{
  //Clean name
  $name = trim($name . " Customer");

  // Load token
  $token = loadToken();
  if (!$token) {

    echo json_encode("Failed to load or refresh token.");
    return;
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

  return;
}

switch ($_SERVER['REQUEST_METHOD']) {
  case 'POST':

    // Handle POST request
    if (empty($_POST)) {
      $_POST = (array) json_decode(file_get_contents("php://input"), true);
    }

    if (isset($_POST['phone'])) {

      if ($phoneNumber = validatePhoneNumber($_POST['phone'])) {

        $name = $_POST['name'] ?? null;
        $email = $_POST['email'] ?? null;

        main($phoneNumber, $name, $email);
      } else {

        echo json_encode("invalid phone number");
      }
    } else {

      echo json_encode("Phone number is required.");
    }
    break;

  case 'OPTIONS':

    // Handle preflight request
    http_response_code(204);
    break;

  default:

    // Method not allowed
    http_response_code(405);
    die(json_encode("Method not allowed: Use POST"));
}

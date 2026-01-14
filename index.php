<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS, GET');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

define('CONFIG_PATH', __DIR__ . '/.ignore/');
define('TOKEN_PATH', CONFIG_PATH . 'token');
define('REDIRECT_URI', "http://localhost:5600");

if (!file_exists(CONFIG_PATH . 'keys.json')) {
  die(json_encode("Missing keys.json in config directory."));
}

define('KEY', json_decode(file_get_contents(CONFIG_PATH . 'keys.json'), true));

define('SALT_LENGTH', 16);
define('IV_LENGTH', 12);
define('TAG_LENGTH', 16);
define('PBKDF2_ITERATIONS', 100000);
define('KEY_LENGTH', 32);

define('SECRETS', json_decode(decryptSecret(file_get_contents(CONFIG_PATH . 'honeypot')), true));

function base64url_decode($data)
{
  $remainder = strlen($data) % 4;
  if ($remainder) $data .= str_repeat('=', 4 - $remainder);
  return base64_decode(strtr($data, '-_', '+/'));
}

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

function getGooglePublicKey(array $jwks, string $kid)
{
  foreach ($jwks as $key) {
    if ($key['kid'] !== $kid) {
      continue;
    }

    // Case 1: x5c certificate
    if (isset($key['x5c'][0])) {
      $certPem =
        "-----BEGIN CERTIFICATE-----\n" .
        chunk_split($key['x5c'][0], 64, "\n") .
        "-----END CERTIFICATE-----\n";

      return openssl_pkey_get_public($certPem);
    }

    // Case 2: raw RSA key (n, e)
    if (isset($key['n'], $key['e'])) {
      $pem = jwkToPem($key['n'], $key['e']);
      return openssl_pkey_get_public($pem);
    }
  }

  return null;
}

function jwkToPem(string $n, string $e): string
{
  $modulus  = base64url_decode($n);
  $exponent = base64url_decode($e);

  // ASN.1 encoding helpers
  $encodeLength = function ($length) {
    if ($length <= 0x7F) {
      return chr($length);
    }
    $temp = ltrim(pack('N', $length), "\x00");
    return chr(0x80 | strlen($temp)) . $temp;
  };

  $encodeInteger = function ($value) use ($encodeLength) {
    if (ord($value[0]) > 0x7F) {
      $value = "\x00" . $value;
    }
    return "\x02" . $encodeLength(strlen($value)) . $value;
  };

  $encodeSequence = function ($value) use ($encodeLength) {
    return "\x30" . $encodeLength(strlen($value)) . $value;
  };

  // RSAPublicKey ::= SEQUENCE { modulus, exponent }
  $rsaPublicKey =
    $encodeSequence(
      $encodeInteger($modulus) .
        $encodeInteger($exponent)
    );

  // AlgorithmIdentifier for rsaEncryption
  $rsaOid = "\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00";

  // SubjectPublicKeyInfo
  $subjectPublicKeyInfo =
    $encodeSequence(
      $rsaOid .
        "\x03" . $encodeLength(strlen($rsaPublicKey) + 1) .
        "\x00" . $rsaPublicKey
    );

  return
    "-----BEGIN PUBLIC KEY-----\n" .
    chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n") .
    "-----END PUBLIC KEY-----\n";
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

function newUser($token): string | null
{
  $payload = [
    "client_id" => SECRETS['client_id'],
    "client_secret" => SECRETS['client_secret'],
    "code" => $token,
    "grant_type" => "authorization_code",
    "redirect_uri" => REDIRECT_URI
  ];

  $newToken = sendCurlRequest(
    "https://oauth2.googleapis.com/token",
    "POST",
    ["Content-Type" => "application/x-www-form-urlencoded"],
    $payload,
  );

  if (isset($newToken['error'])) {

    return $newToken['error'];
  }

  if (! $newToken['response']) die("Error requesting token.");

  $tokenResponse = json_decode($newToken['response'], true);

  $accessToken = $tokenResponse['access_token'] ?? null;
  $refreshToken = $tokenResponse['refresh_token'] ?? null;
  $idToken = $tokenResponse['id_token'] ?? null;
  $expiresIn = $tokenResponse['expires_in'] ?? null;

  if (!$accessToken || !$idToken) die("Invalid token response.");

  list($headerB64, $payloadB64, $sigB64) = explode('.', $idToken);
  $header = json_decode(base64url_decode($headerB64), true);
  $payload = json_decode(base64url_decode($payloadB64), true);
  $signature = base64url_decode($sigB64);

  $kid = $header['kid'] ?? null;
  $alg = $header['alg'] ?? null;

  if ($alg !== 'RS256') die("Unsupported algorithm");

  if (!$kid) die("No key ID in header");
  
  $certsJson = sendCurlRequest(
    "https://www.googleapis.com/oauth2/v3/certs"
  );

  $certsData = json_decode($certsJson['response'], true);

  $keys = $certsData['keys'] ?? [];

  $publicKey = getGooglePublicKey($keys, $kid);

  if (!$publicKey) die("Matching public key not found");

  $verified = openssl_verify(
    "$headerB64.$payloadB64",
    $signature,
    $publicKey,
    OPENSSL_ALGO_SHA256
  );

  if ($verified !== 1) die("Invalid ID token signature");

  if ($payload['iss'] !== 'https://accounts.google.com') die("Invalid issuer");

  if ($payload['aud'] !== SECRETS['client_id']) die("Invalid audience");

  if ($payload['exp'] < time()) die("ID token expired");

  if (empty($payload['email']) || !$payload['email_verified']) die("Email not verified");


  $expiresAt = time() + $expiresIn;

  // Save new token data
  $tokenData = [

    "access_token" => $accessToken,
    "refresh_token" => $refreshToken,
    "user_id" => $payload['sub'],
    "user_email" => $payload['email'],
    "expires_at" => $expiresAt

  ];

  saveToken($tokenData); //We are going to not be doing this

  return True;
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
  print_r(SECRETS);
  return null;
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

  if ($accessToken) {
    saveToken($tokenResponse);
    return $accessToken;
  }

  return "error";
}

function saveToken(array $tokenResponse): void
{

  file_put_contents(TOKEN_PATH, encryptSecret(json_encode($tokenResponse), KEY['token']));
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
  $name = trim($name . " C-" . time());

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

//refreshToken();
//exit();

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

  case 'GET':

    // Handle GET request (for testing)
    //echo json_encode("API is running.");

    if (! empty($_GET['code'])) {
      newUser($_GET['code']);
    }

    break;

  default:

    // Method not allowed
    http_response_code(405);
    die(json_encode("Method not allowed: Use POST"));
}

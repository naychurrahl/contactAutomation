<?php

define('CONFIG_PATH', __DIR__ . '/.ignore/');
define('TOKEN_PATH', CONFIG_PATH . 'token');
define('REDIRECT_URI', "http://localhost:5600/callback");

if (!file_exists(CONFIG_PATH . 'keys.json')) {
  die(json_encode("Missing keys"));
}

define('KEY', json_decode(file_get_contents(CONFIG_PATH . 'keys.json'), true));

define('SALT_LENGTH', 16);
define('IV_LENGTH', 12);
define('TAG_LENGTH', 16);
define('PBKDF2_ITERATIONS', 100000);
define('KEY_LENGTH', 32);
define('SECRETS', file_get_contents(CONFIG_PATH . 'honeypot'));

class Functions
{
  private function base64url_decode($data)
  {
    $remainder = strlen($data) % 4;
    if ($remainder) $data .= str_repeat('=', 4 - $remainder);
    return base64_decode(strtr($data, '-_', '+/'));
  }

  private function decryptSecret(string $encryptedBase64, string $passphrase = KEY['keys']): string
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

  private function encryptSecret(string $plaintext, string $passphrase = KEY['keys']): string
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

  private function extractEmail(string $idToken): null | array
  {
    $SECRETS = json_decode($this->decryptSecret(SECRETS), true);
    
    list($headerB64, $payloadB64, $sigB64) = explode('.', $idToken);
    $header = json_decode($this->base64url_decode($headerB64), true);
    $payload = json_decode($this->base64url_decode($payloadB64), true);
    $signature = $this->base64url_decode($sigB64);

    $kid = $header['kid'] ?? null;
    $alg = $header['alg'] ?? null;

    if ($alg !== 'RS256') return (null);

    if (!$kid) return (null);

    $certsJson = $this->sendCurlRequest(
      "https://www.googleapis.com/oauth2/v3/certs"
    );

    $certsData = json_decode($certsJson['response'], true);

    $keys = $certsData['keys'] ?? [];

    $publicKey = $this->getGooglePublicKey($keys, $kid);

    if (!$publicKey) return (null);

    $verified = openssl_verify(
      "$headerB64.$payloadB64",
      $signature,
      $publicKey,
      OPENSSL_ALGO_SHA256
    );

    if ($verified !== 1) return (null);

    if ($payload['iss'] !== 'https://accounts.google.com') return (null);

    if ($payload['aud'] !== $SECRETS['client_id']) return (null);

    if ($payload['exp'] < time()) return (null);

    if (empty($payload['email']) || !$payload['email_verified']) return (null);

    return [
      "user_id" => $payload['sub'],
      "user_email" => $payload['email'],
    ];
  }

  private function getGooglePublicKey(array $jwks, string $kid)
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
        $pem = $this->jwkToPem($key['n'], $key['e']);
        return openssl_pkey_get_public($pem);
      }
    }

    return null;
  }

  private function jwkToPem(string $n, string $e): string
  {
    $modulus  = $this->base64url_decode($n);
    $exponent = $this->base64url_decode($e);

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

  private function loadToken(): array | null
  {

    if (file_exists(TOKEN_PATH)) {
      $tokenData = json_decode($this->decryptSecret(file_get_contents(TOKEN_PATH), KEY['token']), true);

      if (isset($tokenData['expires_at']) && $tokenData['expires_at'] < time()) {
        // Token has expired
        return $this->refreshToken($tokenData['refresh_token']);
      }

      return $tokenData;
    }

    return null;
  }

  private function refreshToken(string $refreshToken): array | null
  {

    $SECRETS = json_decode($this->decryptSecret(SECRETS), true);

    $newToken = $this->sendCurlRequest(
      "https://oauth2.googleapis.com/token",
      "POST",
      ["Content-Type" => "application/x-www-form-urlencoded"],
      [
        "client_id" => $SECRETS['client_id'],
        "client_secret" => $SECRETS['client_secret'],
        "refresh_token" => $refreshToken,
        "grant_type" => "refresh_token"
      ]
    );

    if (isset($newToken['error'])) {

      return null;
    }

    $tokenResponse = json_decode($newToken['response'], true);

    $accessToken = $tokenResponse['access_token'] ?? null;
    $refreshToken = $tokenResponse['refresh_token'] ?? null;
    $idToken = $tokenResponse['id_token'] ?? null;
    $expiresIn = $tokenResponse['expires_in'] ?? null;

    if (!$accessToken || !$idToken) die("Invalid token response.");

    $payload = $this->extractEmail($idToken);

    if (! $payload) return null;

    $expiresAt = time() + $expiresIn;

    $tokenData = [

      "access_token" => $accessToken,
      "refresh_token" => $refreshToken,
      "user_id" => $payload['sub'],
      "user_email" => $payload['email'],
      "expires_at" => $expiresAt

    ];

    $this->saveToken($tokenData);

    return $tokenData;
  }

  private function saveToken(array $tokenResponse): void
  {

    file_put_contents(TOKEN_PATH, $this->encryptSecret(json_encode($tokenResponse), KEY['token']));
  }

  private function sendCurlRequest(string $url, string $method = "GET", array $headers = [], array | string  | null $body = null): string | array
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

  public function buildLink(){

    session_start();

    $SECRETS = json_decode($this->decryptSecret(SECRETS), true);
    $state = uniqid();

    $link  = "https://accounts.google.com/o/oauth2/v2/auth";
    $link .= "?response_type=code";
    $link .= "&client_id=".$SECRETS['client_id'];
    $link .= "&redirect_uri=". REDIRECT_URI;
    $link .= "&scope=openid email https://www.googleapis.com/auth/contacts";
    $link .= "&access_type=offline";
    $link .= "&state=".$state;

    $_SESSION['state'] = $state;

    die (json_encode(["link" => $link]));
  }

  public function main(string $phone, string | null $name = null, string | null $email = null): void
  {
    //Clean name
    $name = trim($name . " C-" . time());

    // Load token
    $token = $this->loadToken();
    if (!$token) {

      die(json_encode("Failed to load or refresh token."));
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

    $response = $this->sendCurlRequest(
      "https://people.googleapis.com/v1/people:createContact",
      "POST",
      [
        "Authorization: Bearer " . $token,
        "Content-Type: application/json"
      ],
      $contactPayload
    );

    if (isset($response['error'])) {

      die(json_encode("Error: " . $response['error']));
    } else {

      die(json_encode($response['status'] == 200 ? "Success" : "Failed"));
    }
  }

  public function newUser($token): string | null
  {

    $SECRETS = json_decode($this->decryptSecret(SECRETS), true);

    $payload = [
      "client_id" => $SECRETS['client_id'],
      "client_secret" => $SECRETS['client_secret'],
      "code" => $token,
      "grant_type" => "authorization_code",
      "redirect_uri" => REDIRECT_URI
    ];

    $newToken = $this->sendCurlRequest(
      "https://oauth2.googleapis.com/token",
      "POST",
      ["Content-Type" => "application/x-www-form-urlencoded"],
      $payload,
    );

    if (isset($newToken['error'])) {

      die(json_encode($newToken['error']));
    }

    if (! $newToken['response']) die(json_encode("Error requesting token."));

    $tokenResponse = json_decode($newToken['response'], true);

    $accessToken = $tokenResponse['access_token'] ?? null;
    $refreshToken = $tokenResponse['refresh_token'] ?? null;
    $idToken = $tokenResponse['id_token'] ?? null;
    $expiresIn = $tokenResponse['expires_in'] ?? null;

    if (!$accessToken || !$idToken) die(json_encode("Invalid token response."));

    $payload = $this->extractEmail($idToken);

    if (! $payload) die(0);

    $expiresAt = time() + $expiresIn;

    // Save new token data
    $tokenData = [

      "access_token" => $accessToken,
      "refresh_token" => $refreshToken,
      "user_id" => $payload['sub'],
      "user_email" => $payload['email'],
      "expires_at" => $expiresAt

    ];

    $this->saveToken($tokenData); //We are going to not be doing this

    die(json_encode(True));
  }

  public function ping($text): void
  {
    die(json_encode([
      "Time" => time(),
      "Method" => $text,
      "Response" => "Pong!"
    ]));
  }

  public function validatePhoneNumber(string $phone): bool | string
  {
    // Remove common separators
    $clean = preg_replace('/[\s\-\(\)\.]/', '', $phone);

    // Must start with optional + followed by digits only
    if (!preg_match('/^\+?[0-9]{7,15}$/', $clean)) {

      return false;
    }

    return $clean;
  }
}

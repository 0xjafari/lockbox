<?php
/**
 * 🔐 LockBox - Zero-Knowledge Hybrid Encryption Tool
 * No Server Keys Stored | PHP 7.0+ Compatible
 * AES-256-CBC + RSA-2048-OAEP + HMAC-SHA256
 * 
 * ⚠️ SECURITY MODEL:
 * - Server stores NO keys (Public or Private).
 * - Users MUST provide their own keys for encryption/decryption.
 * - Generated keys are shown ONCE and never saved to disk.
 */

// ========== 🔧 CONFIGURATION ==========
// Master Key is still needed for HMAC derivation (integrity check)
// This key does NOT encrypt data, it only signs it to prevent tampering.
$masterKeyEnv = getenv('MASTER_KEY');
define('MASTER_KEY', $masterKeyEnv ?: 'ChangeThisToASecureRandomKey32Chars!');
define('LOG_FILE', __DIR__ . '/logs/encryption.log');
define('DEBUG_MODE', false);

// ========== 🛡️ ERROR HANDLING ==========
if (DEBUG_MODE) {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
} else {
    error_reporting(0);
    ini_set('display_errors', '0');
}

ini_set('log_errors', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.use_strict_mode', '1');

// ========== ✅ EXTENSION CHECK ==========
$required = ['openssl', 'hash', 'session'];
foreach ($required as $ext) {
    if (!extension_loaded($ext)) {
        die("❌ خطا: ماژول {$ext} فعال نیست");
    }
}

// ========== 📝 LOGGING ==========
function secureLog($level, $message, $context = []) {
    $logDir = dirname(LOG_FILE);
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0755, true);
    }
    $timestamp = date('Y-m-d H:i:s');
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
    
    // Sanitize context (never log keys)
    $safeContext = [];
    foreach ($context as $k => $v) {
        if (!preg_match('/(key|secret|password|master|token|private|public)/i', $k)) {
            $safeContext[$k] = is_string($v) ? mb_substr($v, 0, 50) : $v;
        }
    }
    
    $logEntry = "[{$timestamp}] [{$level}] [{$ip}] {$message}";
    if (!empty($safeContext)) {
        $logEntry .= ' ' . json_encode($safeContext, JSON_UNESCAPED_UNICODE);
    }
    $logEntry .= "\n";
    
    @error_log($logEntry, 3, LOG_FILE);
}

// ========== 🔐 CRYPTOGRAPHY CLASS ==========
class SecureEncryptor {
    private $rsaPublicKey = null;
    private $rsaPrivateKey = null;
    private $masterKey;
    
    const AES_CIPHER = 'aes-256-cbc';
    const HMAC_ALGO = 'sha256';
    const RSA_PADDING = OPENSSL_PKCS1_OAEP_PADDING;
    
    public function __construct($masterKey) {
        if (strlen($masterKey) < 32) {
            throw new Exception('پیکربندی نامعتبر');
        }
        $this->masterKey = $masterKey;
    }
    
    public function setRsaPublicKey($key) {
        if (strpos($key, '-----BEGIN PUBLIC KEY-----') === false) {
            throw new Exception('فرمت کلید عمومی نامعتبر است');
        }
        $this->rsaPublicKey = $key;
        return $this;
    }
    
    public function setRsaPrivateKey($key) {
        if (strpos($key, '-----BEGIN PRIVATE KEY-----') === false && 
            strpos($key, '-----BEGIN RSA PRIVATE KEY-----') === false) {
            throw new Exception('فرمت کلید خصوصی نامعتبر است');
        }
        $this->rsaPrivateKey = $key;
        return $this;
    }
    
    public static function generateKeyPair() {
        $config = array(
            'digest_alg' => 'sha512',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        );
        
        $res = openssl_pkey_new($config);
        if (!$res) {
            throw new Exception('خطا در تولید کلید');
        }
        
        openssl_pkey_export($res, $privateKey);
        $details = openssl_pkey_get_details($res);
        $publicKey = $details['key'];
        
        // Keys are returned but NEVER saved to disk
        return array('public' => $publicKey, 'private' => $privateKey);
    }
    
    public static function validatePublicKey($key) {
        if (empty($key) || strpos($key, '-----BEGIN PUBLIC KEY-----') === false) {
            return false;
        }
        $test = @openssl_pkey_get_public($key);
        if ($test === false) {
            return false;
        }
        @openssl_pkey_free($test);
        return true;
    }
    
    public static function validatePrivateKey($key) {
        if (empty($key) || (strpos($key, '-----BEGIN PRIVATE KEY-----') === false && 
            strpos($key, '-----BEGIN RSA PRIVATE KEY-----') === false)) {
            return false;
        }
        $test = @openssl_pkey_get_private($key);
        if ($test === false) {
            return false;
        }
        @openssl_pkey_free($test);
        return true;
    }
    
    private function deriveKey($info, $length = 32) {
        if (function_exists('hash_hkdf')) {
            return hash_hkdf('sha256', $this->masterKey, $length, $info, '');
        }
        return mb_substr(
            hash_hmac('sha256', $info . "\x01" . $this->masterKey, $this->masterKey, true),
            0,
            $length
        );
    }
    
    private function calculateHmac($data, $key) {
        return hash_hmac(self::HMAC_ALGO, $data, $key, true);
    }
    
    private function verifyHmac($data, $receivedHmac, $key) {
        $expected = $this->calculateHmac($data, $key);
        return hash_equals($expected, $receivedHmac);
    }
    
    public function encrypt($plainText) {
        if (empty($plainText)) {
            throw new Exception('متن ورودی خالی است');
        }
        if (!$this->rsaPublicKey) {
            throw new Exception('کلید عمومی الزامی است');
        }
        
        $aesKey = random_bytes(32);
        $ivLength = openssl_cipher_iv_length(self::AES_CIPHER);
        $iv = random_bytes($ivLength);
        
        $ciphertext = openssl_encrypt($plainText, self::AES_CIPHER, $aesKey, OPENSSL_RAW_DATA, $iv);
        if ($ciphertext === false) {
            throw new Exception('رمزنگاری AES شکست خورد');
        }
        
        $hmacKey = $this->deriveKey('hmac-encryption-key');
        $hmac = $this->calculateHmac($iv . $ciphertext, $hmacKey);
        
        if (!openssl_public_encrypt($aesKey, $encryptedAesKey, $this->rsaPublicKey, self::RSA_PADDING)) {
            throw new Exception('رمزنگاری RSA شکست خورد');
        }
        
        $payload = $encryptedAesKey . $iv . $hmac . $ciphertext;
        return base64_encode($payload);
    }
    
    public function decrypt($encodedPayload) {
        if (!$this->rsaPrivateKey) {
            throw new Exception('کلید خصوصی الزامی است');
        }
        
        $data = base64_decode($encodedPayload, true);
        if ($data === false || strlen($data) < 304) {
            throw new Exception('داده نامعتبر است');
        }
        
        $offset = 0;
        $encryptedAesKey = substr($data, $offset, 256);
        $offset += 256;
        
        $ivLength = openssl_cipher_iv_length(self::AES_CIPHER);
        $iv = substr($data, $offset, $ivLength);
        $offset += $ivLength;
        
        $hmacLength = 32;
        $receivedHmac = substr($data, $offset, $hmacLength);
        $offset += $hmacLength;
        
        $ciphertext = substr($data, $offset);
        
        if (!openssl_private_decrypt($encryptedAesKey, $aesKey, $this->rsaPrivateKey, self::RSA_PADDING)) {
            throw new Exception('رمزگشایی شکست خورد - کلید نامعتبر');
        }
        
        $hmacKey = $this->deriveKey('hmac-encryption-key');
        if (!$this->verifyHmac($iv . $ciphertext, $receivedHmac, $hmacKey)) {
            throw new Exception('اعتبارسنجی داده شکست خورد');
        }
        
        $plaintext = openssl_decrypt($ciphertext, self::AES_CIPHER, $aesKey, OPENSSL_RAW_DATA, $iv);
        if ($plaintext === false) {
            throw new Exception('رمزگشایی نهایی شکست خورد');
        }
        
        return $plaintext;
    }
}

// ========== 🎫 CSRF & SESSION ==========
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function generateCsrfToken() {
    if (empty($_SESSION['csrf_token']) || time() - ($_SESSION['csrf_time'] ?? 0) > 1800) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_time'] = time();
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrfToken($token) {
    return !empty($token) && !empty($_SESSION['csrf_token']) && 
           hash_equals($_SESSION['csrf_token'], $token);
}

// ========== 🎮 INITIALIZATION ==========
$errorMessage = '';
$successMessage = '';
$encryptedOutput = '';
$decryptedOutput = '';
$csrfToken = generateCsrfToken();
$generatedKeys = null;
$validationResult = null;

// NO SERVER KEYS LOADED HERE

// ========== 📥 REQUEST HANDLING ==========
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        $errorMessage = 'درخواست نامعتبر است';
    } else {
        $action = $_POST['action'] ?? '';
        
        try {
            switch ($action) {
                case 'encrypt':
                    $plainText = trim($_POST['plainText'] ?? '');
                    $customPublicKey = trim($_POST['publicKey'] ?? '');
                    
                    if ($plainText === '') {
                        throw new Exception('متن ورودی خالی است');
                    }
                    if (empty($customPublicKey)) {
                        throw new Exception('وارد کردن کلید عمومی الزامی است');
                    }
                    if (!SecureEncryptor::validatePublicKey($customPublicKey)) {
                        throw new Exception('کلید عمومی نامعتبر است');
                    }
                    
                    $encryptor = new SecureEncryptor(MASTER_KEY);
                    $encryptor->setRsaPublicKey($customPublicKey);
                    
                    $encryptedOutput = $encryptor->encrypt($plainText);
                    $successMessage = '✅ رمزنگاری با موفقیت انجام شد';
                    break;
                    
                case 'decrypt':
                    $encodedPayload = trim($_POST['encryptedText'] ?? '');
                    $customPrivateKey = trim($_POST['privateKey'] ?? '');
                    
                    if ($encodedPayload === '') {
                        throw new Exception('داده رمزنگاری شده خالی است');
                    }
                    if ($customPrivateKey === '') {
                        throw new Exception('کلید خصوصی الزامی است');
                    }
                    if (!SecureEncryptor::validatePrivateKey($customPrivateKey)) {
                        throw new Exception('کلید خصوصی نامعتبر است');
                    }
                    
                    $encryptor = new SecureEncryptor(MASTER_KEY);
                    $encryptor->setRsaPrivateKey($customPrivateKey);
                    
                    $decryptedOutput = $encryptor->decrypt($encodedPayload);
                    $successMessage = '✅ رمزگشایی با موفقیت انجام شد';
                    break;
                    
                case 'generate_keys':
                    // Generate keys in memory only, do not save to disk
                    $generatedKeys = SecureEncryptor::generateKeyPair();
                    $successMessage = '🔑 جفت کلید جدید تولید شد. همین حالا کلید خصوصی را دانلود و ذخیره کنید! (در سرور ذخیره نشد)';
                    break;
                    
                case 'validate_public':
                    $keyToValidate = trim($_POST['keyToValidate'] ?? '');
                    if (SecureEncryptor::validatePublicKey($keyToValidate)) {
                        $validationResult = ['valid' => true, 'message' => '✅ کلید عمومی معتبر است'];
                    } else {
                        $validationResult = ['valid' => false, 'message' => '❌ کلید عمومی نامعتبر است'];
                    }
                    break;
                    
                case 'validate_private':
                    $keyToValidate = trim($_POST['keyToValidate'] ?? '');
                    if (SecureEncryptor::validatePrivateKey($keyToValidate)) {
                        $validationResult = ['valid' => true, 'message' => '✅ کلید خصوصی معتبر است'];
                    } else {
                        $validationResult = ['valid' => false, 'message' => '❌ کلید خصوصی نامعتبر است'];
                    }
                    break;
                    
                default:
                    $errorMessage = 'عملیات نامعتبر';
            }
        } catch (Exception $e) {
            $errorMessage = '❌ ' . $e->getMessage();
        }
    }
}

$activeTab = $_GET['tab'] ?? 'encrypt';
$validTabs = ['encrypt', 'decrypt', 'keys', 'about'];
if (!in_array($activeTab, $validTabs)) {
    $activeTab = 'encrypt';
}
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔐 LockBox - Zero-Knowledge Encryption</title>
    <style>
        :root{--bg:#121212;--surface:#1e1e1e;--surface-2:#2a2a2a;--text:#e0e0e0;--text-dim:#aaa;--primary:#4caf50;--primary-h:#45a049;--error:#f44336;--success:#2ecc71;--border:#333;--warning:#ffc107}
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:system-ui,-apple-system,'Segoe UI',Tahoma,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:16px}
        .container{max-width:1000px;margin:0 auto;background:var(--surface);border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.4)}
        header{padding:20px 24px;border-bottom:1px solid var(--border);text-align:center}
        header h1{color:var(--primary);font-size:24px}
        .tabs{display:flex;gap:4px;padding:12px 16px;background:var(--surface-2);overflow-x:auto}
        .tab{padding:10px 16px;cursor:pointer;background:transparent;color:var(--text-dim);border:none;border-radius:6px;font-size:14px;white-space:nowrap}
        .tab:hover{background:#333;color:var(--text)}.tab.active{background:var(--primary);color:#fff}
        .tab-content{display:none;padding:20px 24px}.tab-content.active{display:block}
        .form-group{margin-bottom:18px}
        label{display:block;margin-bottom:6px;color:var(--text-dim);font-size:14px}
        textarea{width:100%;padding:12px;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--text);font-family:monospace;min-height:100px;resize:vertical;font-size:12px}
        textarea:focus{outline:none;border-color:var(--primary)}
        textarea[readonly]{background:#151515;color:#777;cursor:not-allowed}
        .btn{padding:12px 24px;background:var(--primary);color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:15px;transition:background .2s}
        .btn:hover{background:var(--primary-h)}.btn.secondary{background:#444}.btn.secondary:hover{background:#555}
        .btn.danger{background:var(--error)}.btn.danger:hover{background:#d32f2f}
        .btn.warning{background:var(--warning);color:#000}.btn.warning:hover{background:#ffb300}
        .btn-group{display:flex;gap:10px;margin-top:12px;flex-wrap:wrap}
        .message{padding:12px 16px;border-radius:8px;margin:16px 0;border-right:3px solid;font-size:14px}
        .message.error{background:rgba(244,67,54,.1);border-color:var(--error);color:#ffcdd2}
        .message.success{background:rgba(46,204,113,.1);border-color:var(--success);color:#c8e6c9}
        .key-block{margin-bottom:20px}
        .key-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:10px}
        .btn-sm{padding:6px 12px;font-size:12px;border-radius:4px}
        .security-card{background:rgba(76,175,80,.08);border-right:3px solid var(--primary);padding:14px;margin:16px 0;font-size:13px}
        .security-card.warning{background:rgba(255,193,7,.08);border-color:var(--warning)}
        .security-card.danger{background:rgba(244,67,54,.08);border-color:var(--error)}
        footer{padding:16px 24px;text-align:center;color:var(--text-dim);font-size:12px;border-top:1px solid var(--border)}
        .mode-btn{padding:8px 16px;background:var(--surface-2);border:1px solid var(--border);border-radius:6px;cursor:pointer;color:var(--text-dim);transition:all .2s}
        .mode-btn.active{background:var(--primary);color:#fff;border-color:var(--primary)}
        .key-status{display:inline-block;padding:4px 8px;border-radius:4px;font-size:12px;margin-right:8px}
        .key-status.valid{background:rgba(46,204,113,.2);color:var(--success)}
        .key-status.invalid{background:rgba(244,67,54,.2);color:var(--error)}
        .key-status.unknown{background:rgba(158,158,158,.2);color:var(--text-dim)}
        @media(max-width:768px){.tabs{flex-wrap:wrap}.tab{flex:1;text-align:center}.btn-group{flex-direction:column}.btn{width:100%}.key-header{flex-direction:column;align-items:stretch}}
        .mono{font-family:monospace}.mt-16{margin-top:16px}.mb-8{margin-bottom:8px}.text-center{text-align:center}.hidden{display:none}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 LockBox</h1>
            <p style="color:var(--text-dim);font-size:13px">Zero-Knowledge Hybrid Encryption | No Server Keys Stored</p>
        </header>
        
        <nav class="tabs">
            <button class="tab <?= $activeTab==='encrypt'?'active':'' ?>" data-tab="encrypt">🔒 رمزنگاری</button>
            <button class="tab <?= $activeTab==='decrypt'?'active':'' ?>" data-tab="decrypt">🔓 رمزگشایی</button>
            <button class="tab <?= $activeTab==='keys'?'active':'' ?>" data-tab="keys">🔑 تولید کلید</button>
            <button class="tab <?= $activeTab==='about'?'active':'' ?>" data-tab="about">ℹ️ درباره</button>
        </nav>
        
        <?php if ($errorMessage): ?>
            <div class="message error"><?= htmlspecialchars($errorMessage) ?></div>
        <?php endif; ?>
        <?php if ($successMessage): ?>
            <div class="message success"><?= htmlspecialchars($successMessage) ?></div>
        <?php endif; ?>
        <?php if ($validationResult): ?>
            <div class="message <?= $validationResult['valid'] ? 'success' : 'error' ?>"><?= htmlspecialchars($validationResult['message']) ?></div>
        <?php endif; ?>
        
        <!-- ENCRYPT -->
        <section id="encrypt" class="tab-content <?= $activeTab==='encrypt'?'active':'' ?>">
            <h2 class="mb-8">رمزنگاری با کلید شخصی</h2>
            
            <div class="security-card warning mb-8">
                ⚠️ <strong>توجه:</strong> سرور هیچ کلیدی ندارد. شما باید کلید عمومی مقصد را وارد کنید.
            </div>
            
            <form method="POST" id="encryptForm">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                <input type="hidden" name="action" value="encrypt">
                
                <div class="form-group">
                    <label>متن ورودی:</label>
                    <textarea name="plainText" required placeholder="متن را وارد کنید..."><?= htmlspecialchars($_POST['plainText'] ?? '') ?></textarea>
                </div>
                
                <div class="form-group">
                    <label>کلید عمومی RSA (مقصد):</label>
                    <textarea name="publicKey" id="publicKey" required placeholder="-----BEGIN PUBLIC KEY-----"><?= htmlspecialchars($_POST['publicKey'] ?? '') ?></textarea>
                    <div class="btn-group">
                        <button type="button" class="btn secondary btn-sm" onclick="validateKey('public')">✅ بررسی صحت</button>
                        <button type="button" class="btn secondary btn-sm" onclick="pasteKey('publicKey')">📋 پیست از کلیپ‌بورد</button>
                    </div>
                </div>
                
                <button type="submit" class="btn">🔐 رمزنگاری کن</button>
            </form>
            
            <?php if ($encryptedOutput): ?>
            <div class="form-group mt-16">
                <label>خروجی رمزنگاری شده:</label>
                <textarea readonly class="mono" onclick="this.select()"><?= htmlspecialchars($encryptedOutput) ?></textarea>
                <div class="btn-group">
                    <button type="button" class="btn secondary btn-sm" onclick="copyText(this)">📋 کپی</button>
                </div>
            </div>
            <?php endif; ?>
        </section>
        
        <!-- DECRYPT -->
        <section id="decrypt" class="tab-content <?= $activeTab==='decrypt'?'active':'' ?>">
            <h2 class="mb-8">رمزگشایی با کلید شخصی</h2>
            
            <div class="security-card danger mb-8">
                ⚠️ <strong>هشدار:</strong> کلید خصوصی خود را وارد کنید. این کلید هرگز در سرور ذخیره نمی‌شود و پس از پردازش از حافظه پاک می‌شود.
            </div>
            
            <form method="POST" id="decryptForm">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                <input type="hidden" name="action" value="decrypt">
                
                <div class="form-group">
                    <label>داده رمزنگاری شده:</label>
                    <textarea name="encryptedText" required placeholder="خروجی Base64"><?= htmlspecialchars($_POST['encryptedText'] ?? '') ?></textarea>
                </div>
                
                <div class="form-group">
                    <label>کلید خصوصی RSA (خودتان):</label>
                    <textarea name="privateKey" id="privateKey" required placeholder="-----BEGIN PRIVATE KEY-----" style="min-height:150px"><?= htmlspecialchars($_POST['privateKey'] ?? '') ?></textarea>
                    <div class="btn-group">
                        <button type="button" class="btn secondary btn-sm" onclick="validateKey('private')">✅ بررسی صحت</button>
                        <button type="button" class="btn secondary btn-sm" onclick="pasteKey('privateKey')">📋 پیست از کلیپ‌بورد</button>
                    </div>
                </div>
                
                <button type="submit" class="btn">🔓 رمزگشایی کن</button>
            </form>
            
            <?php if ($decryptedOutput): ?>
            <div class="form-group mt-16">
                <label>متن اصلی:</label>
                <textarea readonly class="mono" onclick="this.select()"><?= htmlspecialchars($decryptedOutput) ?></textarea>
                <div class="btn-group">
                    <button type="button" class="btn secondary btn-sm" onclick="copyText(this)">📋 کپی</button>
                </div>
            </div>
            <?php endif; ?>
        </section>
        
        <!-- KEYS -->
        <section id="keys" class="tab-content <?= $activeTab==='keys'?'active':'' ?>">
            <h2 class="mb-8">تولید کلید (فقط در مرورگر/حافظه)</h2>
            
            <div class="security-card danger">
                ⚠️ <strong>هشدار بسیار مهم:</strong><br>
                کلیدهایی که اینجا تولید می‌شوند <u>فقط همین یک بار</u> نمایش داده می‌شوند و <strong>هرگز در سرور ذخیره نمی‌شوند</strong>.<br>
                اگر صفحه را رفرش کنید یا کلید خصوصی را دانلود نکنید، <strong>برای همیشه از دست می‌رود</strong>.
            </div>
            
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                <input type="hidden" name="action" value="generate_keys">
                <button type="submit" class="btn warning">🔑 تولید جفت کلید جدید</button>
            </form>
            
            <?php if ($generatedKeys): ?>
            <div class="key-block mt-16">
                <div class="key-header">
                    <label>کلید عمومی (قابل اشتراک‌گذاری):</label>
                    <button class="btn secondary btn-sm" onclick="copyText(this)">📋 کپی</button>
                </div>
                <textarea readonly class="mono" onclick="this.select()"><?= htmlspecialchars($generatedKeys['public']) ?></textarea>
                <small style="color:var(--text-dim);display:block;margin-top:6px">این کلید را به دیگران بدهید تا برای شما پیام رمزنگاری کنند.</small>
            </div>
            
            <div class="key-block">
                <div class="key-header">
                    <label>کلید خصوصی (فقط برای شما - محرمانه):</label>
                    <button class="btn secondary btn-sm" onclick="copyText(this)">📋 کپی</button>
                </div>
                <textarea readonly class="mono" onclick="this.select()" style="min-height:150px; border-color:var(--error)"><?= htmlspecialchars($generatedKeys['private']) ?></textarea>
                <small style="color:var(--error);display:block;margin-top:6px; font-weight:bold;">⚠️ همین حالا این متن را در یک فایل متنی ذخیره کنید و جای امن بگذارید. بعد از بستن این صفحه دیگر دسترسی نخواهید داشت!</small>
            </div>
            <?php endif; ?>
            
            <div class="form-group mt-16">
                <label>اعتبارسنجی کلید موجود:</label>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <textarea name="keyToValidate" placeholder="کلید را برای بررسی وارد کنید..."></textarea>
                    <div class="btn-group">
                        <button type="submit" name="action" value="validate_public" class="btn secondary">بررسی کلید عمومی</button>
                        <button type="submit" name="action" value="validate_private" class="btn secondary">بررسی کلید خصوصی</button>
                    </div>
                </form>
            </div>
        </section>
        
        <!-- ABOUT -->
        <section id="about" class="tab-content <?= $activeTab==='about'?'active':'' ?>">
            <h2 class="mb-8">درباره LockBox</h2>
            <div class="about-section">
                <p>این ابزار بر اساس اصل <strong>Zero-Knowledge (دانش صفر)</strong> کار می‌کند:</p>
                <ul style="margin:10px 20px;line-height:1.8">
                    <li>سرور هیچ کلید عمومی یا خصوصی‌ای را ذخیره نمی‌کند.</li>
                    <li>شما مالک کامل کلیدهای خود هستید.</li>
                    <li>اگر سرور هک شود، هیچ کلیدی برای دزدیدن وجود ندارد.</li>
                </ul>
                
                <div class="security-card">
                    <strong>🔒 معماری امنیتی:</strong><br>
                    AES-256-CBC (داده) + RSA-2048-OAEP (کلید) + HMAC-SHA256 (یکپارچگی)
                </div>
                
                <p class="text-center" style="margin-top:24px;color:var(--text-dim)">github.com/0xjafari</p>
            </div>
        </section>
        
        <footer>
            <p>🔒 تمام عملیات در لحظه انجام می‌شود. هیچ کلید یا داده‌ای روی دیسک ذخیره نمی‌گردد.</p>
        </footer>
    </div>
    
    <script>
        // Tabs
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById(tab.dataset.tab).classList.add('active');
                const url = new URL(window.location);
                url.searchParams.set('tab', tab.dataset.tab);
                window.history.replaceState({}, '', url);
            });
        });
        
        // Copy
        function copyText(btn) {
            const ta = btn.closest('.key-block')?.querySelector('textarea') || 
                       btn.closest('.form-group')?.querySelector('textarea');
            if (!ta) return;
            ta.select();
            navigator.clipboard.writeText(ta.value).then(() => {
                const orig = btn.textContent;
                btn.textContent = '✅ کپی شد';
                setTimeout(() => btn.textContent = orig, 1500);
            }).catch(() => alert('خطا در کپی'));
        }
        
        // Paste
        async function pasteKey(id) {
            try {
                const text = await navigator.clipboard.readText();
                document.getElementById(id).value = text;
            } catch (e) {
                alert('لطفاً به صورت دستی پیست کنید (Ctrl+V)');
            }
        }
        
        // Validate
        function validateKey(type) {
            const id = type === 'public' ? 'publicKey' : 'privateKey';
            const key = document.getElementById(id).value.trim();
            const publicPattern = /-----BEGIN PUBLIC KEY-----/;
            const privatePattern = /-----BEGIN (RSA )?PRIVATE KEY-----/;
            
            if ((type === 'public' && publicPattern.test(key)) || 
                (type === 'private' && privatePattern.test(key))) {
                alert('✅ فرمت کلید صحیح به نظر می‌رسد');
            } else {
                alert('❌ فرمت کلید نامعتبر است');
            }
        }
        
        // Auto-select
        document.querySelectorAll('textarea[readonly]').forEach(el => {
            el.addEventListener('click', function() { this.select(); });
        });
        
        // Form feedback
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', () => {
                const btn = form.querySelector('button[type="submit"]');
                if (btn) {
                    btn.disabled = true;
                    btn.textContent = 'در حال پردازش...';
                }
            });
        });
    </script>
</body>
</html>

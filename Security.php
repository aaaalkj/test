<?php
//Security.php
/**
 * Classe utilitaire pour la gestion de la sécurité optimisée
 * 
 * Version 2.0 - Optimisations apportées :
 * - Centralisation et déduplication des méthodes de validation
 * - Cache intelligent pour les vérifications répétitives
 * - Optimisation du rate limiting avec nettoyage automatique
 * - Simplification de la gestion des tokens avec expiration
 * - Logs de sécurité uniquement pour les événements critiques
 * - Injection de dépendance pour Database résolvant les cycles
 * 
 * @author Système Panier E-commerce
 * @version 2.0
 * @since 2024
 */

// Vérification des dépendances de sécurité
if (!defined('SECURE_ACCESS')) {
    if (class_exists('Logger')) {
        Logger::critical('SECURITY', "Accès direct au fichier Security.php détecté");
    }
    exit('Accès direct au fichier interdit');
}

// Pour simuler un utilisateur resté inactif (forcé via cookie DEBUG_USER_SIMU et DEBUG_INACTIF)
/*if (isset($_COOKIE['DEBUG_USER_SIMU']) && $_COOKIE['DEBUG_USER_SIMU'] === '1') {
$_SESSION['user_id'] = 123456; // simule utilisateur connecté
    if (isset($_COOKIE['DEBUG_INACTIF']) && $_COOKIE['DEBUG_INACTIF'] === '1') {
        // Force la session à sembler inactive depuis 1h (ou tout ce que tu veux)
        $_SESSION['last_activity'] = time() - 3600; // inactif depuis 1h
    }
}*/

// Vérification des constantes de sécurité critiques
$requiredSecurityConstants = ['APP_SECRET_KEY', 'APP_ENCRYPTION_KEY', 'APP_HMAC_KEY'];
foreach ($requiredSecurityConstants as $constant) {
    if (!defined($constant)) {
        if (class_exists('Logger')) {
            Logger::critical('SECURITY', "Constante de sécurité manquante: {$constant}");
        }
        die("Configuration de sécurité incomplète");
    }
}

class Security {
    
    // ================================================================================================
    // PROPRIÉTÉS ET CONFIGURATION
    // ================================================================================================
    
    /**
     * Instance de base de données injectée (résout les dépendances circulaires)
     * @var Database|null
     */
    private static $databaseInstance = null;
    
    /**
     * Cache des vérifications pour éviter les répétitions dans la même requête
     * @var array
     */
    private static $verificationCache = [];
    
    /**
     * Cache des empreintes de session pour optimiser les vérifications
     * @var array
     */
    private static $sessionFingerprintCache = [];
    
    /**
     * Stockage des limiteurs de taux avec nettoyage automatique
     * @var array
     */
    private static $rateLimiters = [];
    
    /**
     * Dernière fois où le nettoyage des caches a été effectué
     * @var int
     */
    private static $lastCacheCleanup = 0;
    
    /**
     * Intervalle de nettoyage des caches (en secondes)
     * @var int
     */
    private static $cacheCleanupInterval = 300; // 5 minutes
    
    /**
     * Callback de log externe (injection de dépendance)
     * @var callable|null
     */

    
    // ================================================================================================
    // INJECTION DE DÉPENDANCES
    // ================================================================================================
    
    /**
     * Injecte une instance de base de données (résout les dépendances circulaires)
     */
    public static function setDatabaseInstance(Database $db) {
        self::$databaseInstance = $db;
        if (class_exists('Logger')) {
            Logger::debug('SECURITY', "Instance Database injectée dans Security");
        }
    }
    
    /**
     * Récupère l'instance de base de données avec fallback
     */
    private static function getDatabase() {
        if (self::$databaseInstance === null) {
            try {
                self::$databaseInstance = Database::getInstance();
                if (class_exists('Logger')) {
                    Logger::debug('SECURITY', "Instance Database récupérée par fallback");
                }
            } catch (Exception $e) {
                if (class_exists('Logger')) {
                    Logger::error('SECURITY', "Impossible d'obtenir l'instance Database: " . $e->getMessage());
                }
                throw new Exception("Base de données non disponible pour les opérations de sécurité");
            }
        }
        return self::$databaseInstance;
    }
    
  
    
    // ================================================================================================
    // GESTION DES TOKENS CSRF OPTIMISÉE
    // ================================================================================================
    
    /**
     * Génère ou récupère un token CSRF valide avec cache intelligent
     */
public static function generateCsrfToken() {
    // ✅ CORRECTION: Validation stricte de l'environnement
    if (!function_exists('random_bytes')) {
        throw new Exception("Environnement cryptographiquement non sécurisé - random_bytes() manquant");
    }
    
    // Vérifier si un token valide existe déjà
    if (isset($_SESSION['csrf_token'], $_SESSION['csrf_token_time'], $_SESSION['csrf_token_strong'])) {
        $age = time() - $_SESSION['csrf_token_time'];
        $expiration = defined('CSRF_TOKEN_EXPIRATION') ? CSRF_TOKEN_EXPIRATION : 1800;
        
        // ✅ CORRECTION: Vérifier que le token existant est fort
        if ($age < $expiration && $_SESSION['csrf_token_strong'] === true) {
            return $_SESSION['csrf_token'];
        }
        
        // ✅ AJOUT: Invalider les tokens faibles
        if (!$_SESSION['csrf_token_strong']) {
            unset($_SESSION['csrf_token'], $_SESSION['csrf_token_time'], $_SESSION['csrf_token_strong']);
            if (class_exists('Logger')) {
                Logger::warning('SECURITY', "Token CSRF faible invalidé et régénéré");
            }
        }
    }
    
    // ✅ CORRECTION: Génération stricte obligatoire
    try {
        $tokenLength = defined('CSRF_TOKEN_LENGTH') ? CSRF_TOKEN_LENGTH : 64;
        
        // ✅ CORRECTION: Validation de la longueur
        if ($tokenLength < 32 || $tokenLength % 2 !== 0) {
            throw new Exception("Longueur de token CSRF invalide: {$tokenLength}");
        }
        
        $token = bin2hex(random_bytes($tokenLength / 2));
        
        // ✅ CORRECTION: Validation de l'entropie générée
        if (strlen(count_chars($token, 3)) < 8) {
            throw new Exception("Token CSRF généré avec entropie insuffisante");
        }
        
        $_SESSION['csrf_token'] = $token;
        $_SESSION['csrf_token_time'] = time();
        $_SESSION['csrf_token_strong'] = true;
        $_SESSION['csrf_token_fingerprint'] = self::generateTokenFingerprint($token);
        
        // ✅ AJOUT: Log de génération sécurisé
        if (class_exists('Logger')) {
            Logger::debug('SECURITY', "Token CSRF fort généré", [
                'token_length' => strlen($token),
                'entropy_chars' => strlen(count_chars($token, 3)),
                'session_id' => substr(session_id(), 0, 8) . '...'
            ]);
        }
        
        return $token;
        
    } catch (Exception $e) {
        // ✅ CORRECTION: Log critique et arrêt strict - AUCUN FALLBACK
        if (class_exists('Logger')) {
            Logger::critical('SECURITY', "ÉCHEC CRITIQUE génération CSRF", [
                'error' => $e->getMessage(),
                'session_id' => session_id(),
                'random_bytes_available' => function_exists('random_bytes')
            ]);
        }
        
        self::logSecurityEvent('critical_error', 'Échec génération token CSRF', [
            'error' => $e->getMessage(),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);
        
        throw new Exception("Impossible de générer un token CSRF sécurisé: " . $e->getMessage());
    }
}
    
    
    
    
    
    
    
    
    
    
    /**
     * Valide un token CSRF avec vérifications d'intégrité
     */
    public static function validateCsrfToken($token) {
        // Cache de vérification pour éviter les validations répétées
        $cacheKey = 'csrf_' . substr($token, 0, 10);
        if (isset(self::$verificationCache[$cacheKey])) {
            return self::$verificationCache[$cacheKey];
        }
        
        $isValid = false;
        
        // Vérifications préliminaires
        if (!isset($_SESSION['csrf_token'], $_SESSION['csrf_token_time'], $_SESSION['csrf_token_fingerprint'])) {
            if (class_exists('Logger')) {
                Logger::warning('SECURITY', "Validation CSRF échouée - Session incomplète");
            }
        } else {
            // Vérifier l'expiration
            $age = time() - $_SESSION['csrf_token_time'];
            $expiration = defined('CSRF_TOKEN_EXPIRATION') ? CSRF_TOKEN_EXPIRATION : 3600;
            
            if ($age > $expiration) {
                if (class_exists('Logger')) {
                    Logger::warning('SECURITY', "Token CSRF expiré", ['age' => $age, 'limit' => $expiration]);
                }
            } else {
                // Vérifier l'intégrité du token
                $expectedFingerprint = self::generateTokenFingerprint($_SESSION['csrf_token']);
                if (!hash_equals($_SESSION['csrf_token_fingerprint'], $expectedFingerprint)) {
                    if (class_exists('Logger')) {
                        Logger::security('SECURITY', "Possible manipulation de token CSRF détectée");
                    }
                    self::logSecurityEvent('security_warning', 'Manipulation de token CSRF détectée', [
                        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                    ]);
                } else {
                    // Vérifier l'égalité du token
                    $isValid = hash_equals($_SESSION['csrf_token'], $token);
                    
                    if (!$isValid && class_exists('Logger')) {
                        Logger::security('SECURITY', "Token CSRF invalide soumis");
                        self::logSecurityEvent('security_warning', 'Token CSRF invalide', [
                            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                        ]);
                    }
                }
            }
        }
        
        // Mettre en cache le résultat
        self::$verificationCache[$cacheKey] = $isValid;
        
        return $isValid;
    }
    
    /**
     * Génère une empreinte pour vérifier l'intégrité du token CSRF
     */
    private static function generateTokenFingerprint($token) {
        return hash_hmac('sha256', $token, APP_HMAC_KEY);
    }
    
    // ================================================================================================
    // VALIDATION ET SANITISATION CENTRALISÉES
    // ================================================================================================
    
    /**
     * Nettoie et valide les entrées utilisateur de manière unifiée
     */

    /**
 * Nettoie et valide les entrées utilisateur de manière unifiée
 */
public static function sanitizeInput($input, $type = 'string') {
    
    // ✅ CORRECTION: Détection stricte des données sensibles
    $sensitiveTypes = ['password', 'token', 'secret', 'key', 'csrf_token', 'session_id'];
    $isSensitiveType = in_array(strtolower($type), $sensitiveTypes);
    $isSensitiveContent = is_string($input) && preg_match('/\b(pass|pwd|token|secret|key|auth|csrf|session)\b/i', $input);
    $isSensitive = $isSensitiveType || $isSensitiveContent;
    
    // ✅ CORRECTION: Validation stricte de type d'entrée
    if (!is_scalar($input) && !is_array($input) && !is_null($input)) {
        if (class_exists('Logger')) {
            Logger::warning('SECURITY', 'Type d\'entrée non supporté pour sanitisation', [
                'input_type' => gettype($input),
                'target_type' => $type
            ]);
        }
        return '';
    }
    
    // Traitement récursif des tableaux avec limitation de profondeur
    if (is_array($input)) {
        static $depth = 0;
        if ($depth > 10) { // ✅ CORRECTION: Prévention DoS par profondeur excessive
            throw new InvalidArgumentException("Profondeur de tableau excessive (max 10)");
        }
        
        $depth++;
        $sanitized = [];
        $count = 0;
        foreach ($input as $key => $value) {
            if ($count > 1000) { // ✅ CORRECTION: Limitation du nombre d'éléments
                throw new InvalidArgumentException("Tableau trop volumineux (max 1000 éléments)");
            }
            $sanitizedKey = self::sanitizeInput($key, 'key');
            $sanitized[$sanitizedKey] = self::sanitizeInput($value, $type);
            $count++;
        }
        $depth--;
        return $sanitized;
    }
    
    // ✅ CORRECTION: Gestion stricte des valeurs null et vides
    if (is_null($input)) {
        return null;
    }
    
    if ($input === '' || $input === false) {
        return '';
    }
    
    // Conversion sécurisée en string avec validation
    $stringInput = (string)$input;
    
    // ✅ CORRECTION: Validation de longueur selon le type
    $maxLengths = [
        'key' => 64,
        'filename' => 255,
        'email' => 320,
        'url' => 2048,
        'string' => 65535,
        'alphanum' => 255
    ];
    
    $maxLength = $maxLengths[$type] ?? $maxLengths['string'];
    if (strlen($stringInput) > $maxLength) {
        throw new InvalidArgumentException("Entrée trop longue pour le type {$type} (max {$maxLength})");
    }
    
    // Traitement selon le type avec validation stricte
    switch ($type) {
        case 'int':
            $result = filter_var($stringInput, FILTER_VALIDATE_INT);
            if ($result === false) {
                throw new InvalidArgumentException("Valeur entière invalide");
            }
            break;
            
        case 'float':
            $result = filter_var($stringInput, FILTER_VALIDATE_FLOAT);
            if ($result === false) {
                throw new InvalidArgumentException("Valeur décimale invalide");
            }
            break;
            
        case 'email':
            $email = filter_var($stringInput, FILTER_SANITIZE_EMAIL);
            $result = filter_var($email, FILTER_VALIDATE_EMAIL);
            if ($result === false) {
                throw new InvalidArgumentException("Format email invalide");
            }
            $result = strtolower(trim($result));
            break;
            
        case 'url':
            $url = filter_var($stringInput, FILTER_SANITIZE_URL);
            $result = filter_var($url, FILTER_VALIDATE_URL);
            if ($result === false) {
                throw new InvalidArgumentException("Format URL invalide");
            }
            break;
            
        case 'filename':
            // ✅ CORRECTION: Validation stricte des noms de fichiers
            $filename = preg_replace('/[^a-zA-Z0-9._-]/', '', $stringInput);
            $filename = str_replace('..', '', $filename);
            if (empty($filename) || $filename === '.' || $filename === '..') {
                throw new InvalidArgumentException("Nom de fichier invalide");
            }
            $result = $filename;
            break;
            
        case 'key':
            $result = preg_replace('/[^a-zA-Z0-9_]/', '', $stringInput);
            if (empty($result)) {
                throw new InvalidArgumentException("Clé invalide - aucun caractère valide");
            }
            break;
            
        case 'alphanum':
            $result = preg_replace('/[^a-zA-Z0-9]/', '', $stringInput);
            break;
            
        case 'string':
        default:
            // ✅ CORRECTION: Nettoyage strict des caractères dangereux
            $cleaned = htmlspecialchars(trim($stringInput), ENT_QUOTES | ENT_HTML5, 'UTF-8');
            // Supprimer les caractères de contrôle
            $result = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $cleaned);
            break;
    }
    
    // ✅ CORRECTION: Log sécurisé seulement en cas de modification significative
    if (class_exists('Logger') && strlen($stringInput) !== strlen((string)$result)) {
        Logger::debug('SECURITY', 'Input modifié lors de la sanitisation', [
            'type' => $type,
            'original_length' => strlen($stringInput),
            'result_length' => strlen((string)$result),
            'is_sensitive' => $isSensitive
        ]);
    }
    
    return $result;
}

/**
 * ✅ NOUVELLE MÉTHODE : Utilitaire pour créer des contextes de log sécurisés
 */
private static function createSafeLogContext($input, $type, $result) {
    $sensitivePatterns = [
        '/\b(password|pwd|pass|token|secret|key|auth|csrf|session|hash)\b/i',
        '/\b[A-Fa-f0-9]{32,}\b/', // Hashes potentiels
        '/\b[A-Za-z0-9+\/]{20,}={0,2}\b/' // Base64 potentiel
    ];
    
    $isSensitiveType = in_array(strtolower($type), ['password', 'token', 'secret', 'key', 'csrf_token']);
    $isSensitiveContent = false;
    
    if (is_string($input)) {
        foreach ($sensitivePatterns as $pattern) {
            if (preg_match($pattern, $input)) {
                $isSensitiveContent = true;
                break;
            }
        }
    }
    
    $isSensitive = $isSensitiveType || $isSensitiveContent;
    
    return [
        'original_type' => gettype($input),
        'target_type' => $type,
        'result_type' => gettype($result),
        'original_value' => $isSensitive ? '[REDACTED_SENSITIVE]' : (is_scalar($input) ? substr((string)$input, 0, 50) : gettype($input)),
        'sanitized_value' => $isSensitive ? '[REDACTED_SENSITIVE]' : (is_scalar($result) ? substr((string)$result, 0, 50) : gettype($result)),
        'is_sensitive' => $isSensitive,
        'length_original' => is_string($input) ? strlen($input) : 0,
        'length_result' => is_string($result) ? strlen($result) : 0
    ];
}
    
    /**
     * Valide les entrées avec règles centralisées et cache
     */
    public static function validateInput($input, $type, $options = []) {
        
            // LOG D'ENTRÉE
    if (class_exists('Logger')) {
        Logger::debug('SECURITY', 'Input validation started', [
            'input' => is_scalar($input) ? $input : gettype($input),
            'type' => $type,
            'options' => array_keys($options)
        ]);
    }
        
        // Cache pour éviter les validations répétitives
        $cacheKey = 'validate_' . md5(serialize([$input, $type, $options]));
        if (isset(self::$verificationCache[$cacheKey])) {
            return self::$verificationCache[$cacheKey];
        }
        
        $isValid = false;
        
        switch ($type) {
            case 'int':
                $min = $options['min'] ?? null;
                $max = $options['max'] ?? null;
                $filterOptions = [];
                
                if ($min !== null) $filterOptions['min_range'] = $min;
                if ($max !== null) $filterOptions['max_range'] = $max;
                
                $isValid = filter_var($input, FILTER_VALIDATE_INT, [
                    'options' => $filterOptions
                ]) !== false;
                break;
                
            case 'float':
                $min = $options['min'] ?? null;
                $max = $options['max'] ?? null;
                $result = filter_var($input, FILTER_VALIDATE_FLOAT);
                
                $isValid = $result !== false &&
                          ($min === null || $result >= $min) &&
                          ($max === null || $result <= $max);
                break;
                
            case 'email':
                $isValid = filter_var($input, FILTER_VALIDATE_EMAIL) !== false;
                
                // Vérification des domaines bannis
                if ($isValid && isset($options['banned_domains'])) {
                    $domain = strtolower(substr(strrchr($input, "@"), 1));
                    $isValid = !in_array($domain, $options['banned_domains']);
                }
                break;
                
            case 'url':
                $isValid = filter_var($input, FILTER_VALIDATE_URL) !== false;
                
                // Vérification des protocoles autorisés
                if ($isValid && isset($options['protocols'])) {
                    $urlParts = parse_url($input);
                    $isValid = isset($urlParts['scheme']) && 
                              in_array($urlParts['scheme'], $options['protocols']);
                }
                break;
                
            case 'productId':
                $isValid = is_numeric($input) && $input > 0 && floor($input) == $input;
                
                // Vérification en base de données si requise
                if ($isValid && !isset($options['skip_db_check'])) {
                    try {
                        $db = self::getDatabase();
                        $count = $db->queryValue("SELECT COUNT(*) FROM products WHERE id = ?", [$input]);
                        $isValid = $count > 0;
                    } catch (Exception $e) {
                        if (class_exists('Logger')) {
                            Logger::error('SECURITY', "Erreur validation productId: " . $e->getMessage());
                        }
                        $isValid = false;
                    }
                }
                break;
                
            case 'quantity':
                $max = $options['max'] ?? 100;
                $isValid = is_numeric($input) && $input > 0 && 
                          floor($input) == $input && $input <= $max;
                break;
                
            case 'password':
                $minLength = $options['min_length'] ?? 8;
                $requireMixed = $options['require_mixed'] ?? true;
                $requireSpecial = $options['require_special'] ?? true;
                
                $isValid = strlen($input) >= $minLength;
                
                if ($isValid && $requireMixed) {
                    $isValid = preg_match('/[a-z]/', $input) && 
                              preg_match('/[A-Z]/', $input) && 
                              preg_match('/[0-9]/', $input);
                }
                
                if ($isValid && $requireSpecial) {
                    $isValid = preg_match('/[^a-zA-Z0-9]/', $input);
                }
                break;
                
            case 'date':
                $format = $options['format'] ?? 'Y-m-d';
                $dateTime = DateTime::createFromFormat($format, $input);
                $isValid = $dateTime && $dateTime->format($format) === $input;
                
                if ($isValid) {
                    if (isset($options['min_date'])) {
                        $minDate = new DateTime($options['min_date']);
                        $isValid = $dateTime >= $minDate;
                    }
                    
                    if ($isValid && isset($options['max_date'])) {
                        $maxDate = new DateTime($options['max_date']);
                        $isValid = $dateTime <= $maxDate;
                    }
                }
                break;
                
            default:
                $isValid = !empty($input);
                break;
        }
        
               // LOG DE SORTIE (juste avant le return final)
        if (class_exists('Logger')) {
            Logger::debug('SECURITY', 'Input validation result', [
                'input' => is_scalar($input) ? $input : gettype($input),
                'type' => $type,
                'valid' => $isValid,
                'options_applied' => !empty($options)
            ]);
        }
        
        
        // Mettre en cache le résultat
        self::$verificationCache[$cacheKey] = $isValid;
        
        return $isValid;
    }
    
    // ================================================================================================
    // CHIFFREMENT ET SIGNATURES HMAC
    // ================================================================================================
    
    /**
     * Génère une signature HMAC pour un contenu
     */
    public static function generateHmac($data) {
        $serialized = serialize($data);
        return hash_hmac('sha256', $serialized, APP_HMAC_KEY);
    }
    
    /**
     * Vérifie une signature HMAC
     */
    public static function verifyHmac($data, $signature) {
        $expectedSignature = self::generateHmac($data);
        $isValid = hash_equals($expectedSignature, $signature);
        
        if (!$isValid && class_exists('Logger')) {
            Logger::security('SECURITY', "Tentative de manipulation de données signées détectée");
            self::logSecurityEvent('security_warning', 'Manipulation de données HMAC', [
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
        }
        
        return $isValid;
    }
    



    
    
public static function encrypt($data) {
    try {
        $serialized = serialize($data);
        $cipher = defined('ENCRYPTION_CIPHER') ? ENCRYPTION_CIPHER : 'aes-256-gcm';

        // Vérifier la disponibilité du cipher
        if (!in_array($cipher, openssl_get_cipher_methods())) {
            $cipher = 'aes-256-cbc';
        }

        $ivlen = openssl_cipher_iv_length($cipher);
        $iv = random_bytes($ivlen);
        $tagLength = defined('ENCRYPTION_TAG_LENGTH') ? ENCRYPTION_TAG_LENGTH : 16;

      if (strpos($cipher, 'gcm') !== false) {
    // ✅ CORRECTION : Initialisation correcte du tag
    $tag = null;
    
    // Mode GCM avec authentification intégrée
    $ciphertext = openssl_encrypt($serialized, $cipher, APP_ENCRYPTION_KEY, OPENSSL_RAW_DATA, $iv, $tag, '', $tagLength);
    
    // ✅ CORRECTION : Vérification immédiate et complète
    if ($ciphertext === false || $tag === null || strlen($tag) !== $tagLength) {
        // Nettoyage sécurisé en cas d'échec
        if (function_exists('sodium_memzero')) {
            sodium_memzero($serialized);
        }
        throw new Exception("Échec du chiffrement GCM ou génération du tag d'authentification");
    }
    
    $encrypted = $iv . $tag . $ciphertext;
}else {
            // Mode CBC avec HMAC pour l'authentification (inchangé - déjà sécurisé)
            $ciphertext = openssl_encrypt($serialized, $cipher, APP_ENCRYPTION_KEY, OPENSSL_RAW_DATA, $iv);
            if ($ciphertext === false) {
                throw new Exception("Échec du chiffrement CBC");
            }
            $hmac = hash_hmac('sha256', $iv . $ciphertext, APP_HMAC_KEY, true);
            $encrypted = $iv . $hmac . $ciphertext;
        }

        // ✅ AJOUT : Nettoyage sécurisé de la mémoire
        if (function_exists('sodium_memzero')) {
            sodium_memzero($serialized);
        }

        return base64_encode($encrypted);

    } catch (Exception $e) {
        if (class_exists('Logger')) {
            Logger::error('SECURITY', "Erreur chiffrement: " . $e->getMessage());
        }
        return false;
    }
}
    
    /**
     * Déchiffre des données sécurisées
     */
public static function decrypt($data) {
    $decrypted = null;
    $serialized = null;
    
    try {
        $decoded = base64_decode($data);
        if ($decoded === false) {
            throw new Exception("Données base64 invalides");
        }
        
        $cipher = defined('ENCRYPTION_CIPHER') ? ENCRYPTION_CIPHER : 'aes-256-gcm';
        if (!in_array($cipher, openssl_get_cipher_methods())) {
            $cipher = 'aes-256-cbc';
        }
        
        $ivlen = openssl_cipher_iv_length($cipher);
        if (strlen($decoded) <= $ivlen) {
            throw new Exception("Données chiffrées trop courtes");
        }
        
        $iv = substr($decoded, 0, $ivlen);
        
        if (strpos($cipher, 'gcm') !== false) {
            // Mode GCM
            $tagLength = defined('ENCRYPTION_TAG_LENGTH') ? ENCRYPTION_TAG_LENGTH : 16;
            if (strlen($decoded) <= $ivlen + $tagLength) {
                throw new Exception("Données GCM trop courtes");
            }
            
            $tag = substr($decoded, $ivlen, $tagLength);
            $ciphertext = substr($decoded, $ivlen + $tagLength);
            
            $decrypted = openssl_decrypt($ciphertext, $cipher, APP_ENCRYPTION_KEY, OPENSSL_RAW_DATA, $iv, $tag);
        } else {
            // Mode CBC avec HMAC
            $hmacLength = 32;
            if (strlen($decoded) <= $ivlen + $hmacLength) {
                throw new Exception("Données CBC trop courtes");
            }
            
            $hmac = substr($decoded, $ivlen, $hmacLength);
            $ciphertext = substr($decoded, $ivlen + $hmacLength);
            
            // Vérifier le HMAC
            $expectedHmac = hash_hmac('sha256', $iv . $ciphertext, APP_HMAC_KEY, true);
            if (!hash_equals($hmac, $expectedHmac)) {
                throw new Exception("Authentification des données échouée");
            }
            
            $decrypted = openssl_decrypt($ciphertext, $cipher, APP_ENCRYPTION_KEY, OPENSSL_RAW_DATA, $iv);
        }
        
        if ($decrypted === false) {
            throw new Exception("Échec du déchiffrement");
        }
        
        // ✅ CORRECTION: Désérialisation avec nettoyage
        $result = unserialize($decrypted);
        
        // ✅ CORRECTION: Nettoyage sécurisé complet
        if (function_exists('sodium_memzero')) {
            sodium_memzero($decrypted);
            sodium_memzero($decoded);
        } else {
            // ✅ FALLBACK: Surcharge des variables sensibles
            $decrypted = str_repeat("\0", strlen($decrypted));
            $decoded = str_repeat("\0", strlen($decoded));
        }
        
        return $result;
        
    } catch (Exception $e) {
        // ✅ CORRECTION: Nettoyage même en cas d'erreur
        if ($decrypted !== null && function_exists('sodium_memzero')) {
            sodium_memzero($decrypted);
        }
        
        if (class_exists('Logger')) {
            Logger::error('SECURITY', "Erreur déchiffrement: " . $e->getMessage());
        }
        return null;
    }
}
    
    
    
    // ================================================================================================
    // RATE LIMITING OPTIMISÉ
    // ================================================================================================
    
public static function rateLimiter($key, $limit = null, $period = 60) {
    if ($limit === null) {
        $limit = defined('RATE_LIMIT') ? RATE_LIMIT : 60;
    }
    
    // ✅ CORRECTION: Validation stricte de la clé
    if (!is_string($key) || empty($key) || strlen($key) > 64) {
        throw new InvalidArgumentException("Clé de rate limiting invalide");
    }
    
    // ✅ CORRECTION: Validation stricte du format de clé (pas de caractères dangereux)
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $key)) {
        throw new InvalidArgumentException("Format de clé de rate limiting invalide - caractères non autorisés");
    }
    
    // Nettoyage périodique des caches
    self::cleanupCachesIfNeeded();
    
    $currentTime = time();
    $sessionKey = 'rate_limit_' . $key;
    
    // Vérifier que la session est active
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    // ✅ CORRECTION: Vérification d'intégrité du rate limiter
    if (isset($_SESSION[$sessionKey]) && !is_array($_SESSION[$sessionKey])) {
        unset($_SESSION[$sessionKey]);
        self::logSecurityEvent('security_warning', 'Rate limiter corrompu détecté', [
            'key' => $key,
            'corrupted_value' => gettype($_SESSION[$sessionKey])
        ]);
    }
    
    // Initialiser si première requête
    if (!isset($_SESSION[$sessionKey])) {
        $_SESSION[$sessionKey] = [
            'count' => 1, 
            'time' => $currentTime, 
            'blocked_until' => 0,
            'created' => $currentTime,
            'key_hash' => hash('sha256', $key . session_id())
        ];
        return true;
    }
    
    $rateData = $_SESSION[$sessionKey];
    
    // ✅ CORRECTION: Validation de l'intégrité des données
    $expectedHash = hash('sha256', $key . session_id());
    if (!isset($rateData['key_hash']) || !hash_equals($rateData['key_hash'], $expectedHash)) {
        unset($_SESSION[$sessionKey]);
        self::logSecurityEvent('security_warning', 'Tentative de manipulation rate limiter', [
            'key' => $key,
            'session_id' => session_id()
        ]);
        return false;
    }
    
    // Vérifier si bloqué
    if ($rateData['blocked_until'] > $currentTime) {
        if (class_exists('Logger')) {
            Logger::security('SECURITY', "Rate limit - Accès bloqué", [
                'key' => $key,
                'remaining_time' => $rateData['blocked_until'] - $currentTime
            ]);
        }
        return false;
    }
    
    // Réinitialiser si période écoulée
    if (($currentTime - $rateData['time']) > $period) {
        $_SESSION[$sessionKey] = [
            'count' => 1, 
            'time' => $currentTime, 
            'blocked_until' => 0,
            'created' => $rateData['created'],
            'key_hash' => $expectedHash,
            'reset_count' => ($rateData['reset_count'] ?? 0) + 1
        ];
        return true;
    }
    
    // ✅ CORRECTION: Opération atomique sécurisée
    $newCount = $rateData['count'] + 1;
    
    if ($newCount > $limit) {
        $blockTime = defined('RATE_LIMIT_TIMEOUT') ? RATE_LIMIT_TIMEOUT : 300;
        $_SESSION[$sessionKey]['blocked_until'] = $currentTime + $blockTime;
        $_SESSION[$sessionKey]['count'] = $newCount;
        $_SESSION[$sessionKey]['blocked_at'] = $currentTime;
        
        if (class_exists('Logger')) {
            Logger::security('SECURITY', "Rate limit dépassé", [
                'key' => $key,
                'count' => $newCount,
                'limit' => $limit,
                'blocked_for' => $blockTime
            ]);
        }
        
        self::logSecurityEvent('security_warning', 'Limite de taux dépassée', [
            'key' => $key,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'count' => $newCount,
            'limit' => $limit
        ]);
        
        return false;
    }
    
    // ✅ CORRECTION: Mise à jour atomique avec validation
    $_SESSION[$sessionKey]['count'] = $newCount;
    $_SESSION[$sessionKey]['last_access'] = $currentTime;
    
    return true;
}
    
    // ================================================================================================
    // GESTION DES SESSIONS SÉCURISÉES
    // ================================================================================================
    
    /**
     * Vérifie l'empreinte de session avec cache optimisé
     */
// ... début du fichier inchangé ...

public static function checkSessionFingerprint($strict = true) { // ✅ CORRECTION: strict par défaut
    $sessionId = session_id();
    $cacheKey = "_fingerprint_verified_{$sessionId}";

    if (isset($_SESSION[$cacheKey])) {
        return $_SESSION[$cacheKey];
    }

    if (!isset($_SESSION['fingerprint'])) {
        $_SESSION['fingerprint'] = self::generateSessionFingerprint();
        $_SESSION['fingerprint_created'] = time();
        $_SESSION[$cacheKey] = true;
        return true;
    }

    $currentFingerprint = self::generateSessionFingerprint();

    if ($strict) {
        $isValid = hash_equals($_SESSION['fingerprint'], $currentFingerprint);

        if (!$isValid) {
            if (class_exists('Logger')) {
                Logger::security('SECURITY', "Empreinte de session invalide (mode strict)");
            }
            self::logSecurityEvent('security_warning', 'Possible détournement de session', [
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ]);
        }
    } else {
        // ✅ CORRECTION: Mode non-strict plus strict (90% au lieu de 80%)
        $similarity = 0;
        $length = min(strlen($_SESSION['fingerprint']), strlen($currentFingerprint));
        if ($length === 0) {
            $isValid = false;
        } else {
            for ($i = 0; $i < $length; $i++) {
                if ($_SESSION['fingerprint'][$i] === $currentFingerprint[$i]) {
                    $similarity++;
                }
            }
            $similarityPercentage = ($similarity / $length) * 100;
            $threshold = 90; // ✅ CORRECTION: Seuil augmenté de 80% à 90%
            $isValid = $similarityPercentage >= $threshold;

            if (!$isValid) {
                if (class_exists('Logger')) {
                    Logger::security('SECURITY', "Empreinte de session invalide", [
                        'similarity' => round($similarityPercentage, 1) . '%',
                        'threshold' => $threshold . '%'
                    ]);
                }
            } else if ($similarityPercentage < 100) {
                $_SESSION['fingerprint'] = $currentFingerprint;
            }
        }
    }

    $_SESSION[$cacheKey] = $isValid;
    return $isValid;
}



    
    /**
     * Génère une empreinte de session sécurisée
     */
    private static function generateSessionFingerprint() {
        $factors = [
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            $_SERVER['HTTP_ACCEPT'] ?? 'unknown',
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'unknown'
        ];
        
        // Sel de session persistant
        if (!isset($_SESSION['fingerprint_salt'])) {
            $_SESSION['fingerprint_salt'] = bin2hex(random_bytes(16));
        }
        $factors[] = $_SESSION['fingerprint_salt'];
        
        return hash('sha256', implode('|', $factors));
    }
    
    /**
     * Régénère l'ID de session de manière sécurisée
     */
    public static function regenerateSession() {
        try {
            $sessionData = $_SESSION;
            
            if (!session_regenerate_id(true)) {
                return false;
            }
            
            $_SESSION = $sessionData;
            $_SESSION['last_activity'] = time();
            $_SESSION['fingerprint'] = self::generateSessionFingerprint();
            $_SESSION['security_token'] = bin2hex(random_bytes(16));
            
            return true;
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURITY', "Erreur régénération session: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * Nettoie les données sensibles de la session
     */
    public static function cleanupSession() {
        $keysToKeep = ['csrf_token', 'csrf_token_time', 'fingerprint_salt'];
        $dataToKeep = array_intersect_key($_SESSION, array_flip($keysToKeep));
        
        $_SESSION = $dataToKeep;
        $_SESSION['last_activity'] = time();
        session_regenerate_id(true);
        
        if (class_exists('Logger')) {
            Logger::debug('SECURITY', "Session nettoyée");
        }
        
        return true;
    }
    
    // ================================================================================================
    // TOKENS DE PANIER ET JWT
    // ================================================================================================
    
    /**
     * Génère un token unique pour un panier
     */
    public static function generateCartToken($cartId, $sessionId) {
        try {
            $data = [
                'cart_id' => $cartId,
                'session_id' => $sessionId,
                'timestamp' => time(),
                'random' => bin2hex(random_bytes(8))
            ];
            
            return hash_hmac('sha256', serialize($data), APP_HMAC_KEY);
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURITY', "Erreur génération token panier: " . $e->getMessage());
            }
            // Fallback
            return hash('sha256', $cartId . $sessionId . time() . mt_rand());
        }
    }
    
    /**
     * Vérifie la validité d'un token de panier
     */
    public static function verifyCartToken($token, $cartId, $sessionId) {
        try {
            $db = self::getDatabase();
            $count = $db->queryValue(
                "SELECT COUNT(*) FROM carts WHERE cart_id = ? AND cart_token = ? AND session_id = ?",
                [$cartId, $token, $sessionId]
            );
            
            $isValid = $count > 0;
            
            if (!$isValid && class_exists('Logger')) {
                Logger::security('SECURITY', "Token de panier invalide", ['cart_id' => $cartId]);
                self::logSecurityEvent('security_warning', 'Token de panier invalide', [
                    'cart_id' => $cartId,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
            }
            
            return $isValid;
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURITY', "Erreur vérification token panier: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * Génère un token JWT pour les API internes
     */
    public static function generateAuthToken($data, $expiration = 3600) {
        try {
            $header = ['typ' => 'JWT', 'alg' => 'HS256'];
            $payload = array_merge([
                'iat' => time(),
                'exp' => time() + $expiration,
                'jti' => bin2hex(random_bytes(16))
            ], $data);
            
            $encodedHeader = self::base64UrlEncode(json_encode($header));
            $encodedPayload = self::base64UrlEncode(json_encode($payload));
            
            $signature = hash_hmac('sha256', $encodedHeader . '.' . $encodedPayload, APP_SECRET_KEY, true);
            $encodedSignature = self::base64UrlEncode($signature);
            
            return $encodedHeader . '.' . $encodedPayload . '.' . $encodedSignature;
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURITY', "Erreur génération JWT: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * Vérifie un token JWT
     */
    public static function verifyAuthToken($token) {
        try {
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                throw new Exception("Format JWT invalide");
            }
            
            list($encodedHeader, $encodedPayload, $encodedSignature) = $parts;
            
            // Vérifier la signature
            $signature = self::base64UrlDecode($encodedSignature);
            $expectedSignature = hash_hmac('sha256', $encodedHeader . '.' . $encodedPayload, APP_SECRET_KEY, true);
            
            if (!hash_equals($signature, $expectedSignature)) {
                if (class_exists('Logger')) {
                    Logger::security('SECURITY', "JWT signature invalide");
                }
                self::logSecurityEvent('security_warning', 'JWT signature invalide', [
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
                return false;
            }
            
            // Décoder et vérifier l'expiration
            $payload = json_decode(self::base64UrlDecode($encodedPayload), true);
            
            if (isset($payload['exp']) && $payload['exp'] < time()) {
                return false; // Token expiré
            }
            
            return $payload;
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURITY', "Erreur vérification JWT: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * Encode en Base64Url pour JWT
     */
    private static function base64UrlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    
    /**
     * Décode du Base64Url pour JWT
     */
  /*  private static function base64UrlDecode($data) {
        return base64_decode(strtr($data, '-_', '+/'));
    }*/
    private static function base64UrlDecode($data) {
    $remainder = strlen($data) % 4;
    if ($remainder) {
        $data .= str_repeat('=', 4 - $remainder);
    }
    return base64_decode(strtr($data, '-_', '+/'));
}
    
    
    // ================================================================================================
    // GÉNÉRATION DE NONCES ET HEADERS DE SÉCURITÉ
    // ================================================================================================
    
    /**
     * Génère un nonce unique pour CSP
     */
  /*  public static function generateNonce() {
/**
 * ✅ CORRECTION COMPLÈTE: Génération de nonce CSP avec gestion mémoire optimisée
 */
public static function generateNonce() {
    // Validation de l'environnement cryptographique
    if (!function_exists('random_bytes')) {
        if (class_exists('Logger')) {
            Logger::critical('SECURITY', "random_bytes() non disponible - environnement non sécurisé");
        }
        throw new Exception("Impossible de générer un nonce sécurisé - random_bytes() non disponible");
    }
    
    // Générer le nonce (32 caractères hex = 16 bytes)
    try {
        $nonce = bin2hex(random_bytes(16));
    } catch (Exception $e) {
        if (class_exists('Logger')) {
            Logger::critical('SECURITY', "Échec génération nonce: " . $e->getMessage());
        }
        throw new Exception("Échec de la génération cryptographique du nonce: " . $e->getMessage());
    }
    
    // Initialiser le tableau des nonces si nécessaire
    if (!isset($_SESSION['csp_nonces'])) {
        $_SESSION['csp_nonces'] = [];
    }
    
    // ✅ CORRECTION: Nettoyage préventif avec limite stricte
    $maxNonces = 25; // Limite stricte pour hébergement mutualisé
    $now = time();
    $maxAge = 3600; // 1 heure de validité
    
    if (count($_SESSION['csp_nonces']) >= $maxNonces) {
        // Étape 1: Supprimer les nonces expirés
        $expiredCount = 0;
        foreach ($_SESSION['csp_nonces'] as $existingNonce => $timestamp) {
            if ($now - $timestamp > $maxAge) {
                unset($_SESSION['csp_nonces'][$existingNonce]);
                $expiredCount++;
            }
        }
        
        // Étape 2: Si encore trop de nonces, appliquer FIFO strict
        if (count($_SESSION['csp_nonces']) >= $maxNonces) {
            // Trier par timestamp (plus ancien en premier)
            asort($_SESSION['csp_nonces']);
            
            // Garder seulement les plus récents
            $keepCount = intval($maxNonces * 0.7); // Garder 70% de la limite
            $_SESSION['csp_nonces'] = array_slice($_SESSION['csp_nonces'], -$keepCount, null, true);
            
            if (class_exists('Logger')) {
                Logger::debug('SECURITY', "Nettoyage FIFO des nonces CSP appliqué", [
                    'expired_removed' => $expiredCount,
                    'fifo_removed' => (count($_SESSION['csp_nonces']) + $expiredCount) - $keepCount,
                    'remaining_nonces' => count($_SESSION['csp_nonces']),
                    'max_allowed' => $maxNonces
                ]);
            }
        } else {
            if (class_exists('Logger')) {
                Logger::debug('SECURITY', "Nettoyage par expiration des nonces CSP", [
                    'expired_removed' => $expiredCount,
                    'remaining_nonces' => count($_SESSION['csp_nonces']),
                    'max_allowed' => $maxNonces
                ]);
            }
        }
    }
    
    // ✅ CORRECTION: Vérifier l'unicité du nonce généré
    $attempts = 0;
    $maxAttempts = 10;
    
    while (isset($_SESSION['csp_nonces'][$nonce]) && $attempts < $maxAttempts) {
        // Collision détectée, générer un nouveau nonce
        try {
            $nonce = bin2hex(random_bytes(16));
            $attempts++;
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURITY', "Échec regénération nonce après collision: " . $e->getMessage());
            }
            throw new Exception("Impossible de générer un nonce unique");
        }
    }
    
    // Vérifier qu'on n'a pas épuisé les tentatives
    if ($attempts >= $maxAttempts) {
        if (class_exists('Logger')) {
            Logger::error('SECURITY', "Impossible de générer un nonce unique après {$maxAttempts} tentatives");
        }
        throw new Exception("Impossible de générer un nonce unique - trop de collisions");
    }
    
    // ✅ CORRECTION: Stocker le nonce avec timestamp
    $_SESSION['csp_nonces'][$nonce] = $now;
    
    // ✅ AJOUT: Logging conditionnel selon l'environnement
    if (class_exists('Logger') && defined('ENVIRONMENT') && ENVIRONMENT === 'development') {
        Logger::debug('SECURITY', "Nonce CSP généré avec succès", [
            'nonce' => substr($nonce, 0, 8) . '...',
            'total_nonces' => count($_SESSION['csp_nonces']),
            'generation_attempts' => $attempts + 1,
            'session_id' => substr(session_id(), 0, 8) . '...'
        ]);
    }
    
    return $nonce;
}

/**
 * ✅ CORRECTION: Validation de nonce avec vérifications supplémentaires
 */
public static function validateNonce($nonce) {
    // Validation des paramètres d'entrée
    if (!is_string($nonce) || empty($nonce)) {
        if (class_exists('Logger')) {
            Logger::warning('SECURITY', "Tentative de validation avec nonce invalide", [
                'nonce_type' => gettype($nonce),
                'nonce_empty' => empty($nonce)
            ]);
        }
        return false;
    }
    
    // Validation du format du nonce (32 caractères hexadécimaux)
    if (strlen($nonce) !== 32 || !ctype_xdigit($nonce)) {
        if (class_exists('Logger')) {
            Logger::warning('SECURITY', "Format de nonce invalide", [
                'nonce_length' => strlen($nonce),
                'nonce_hex_valid' => ctype_xdigit($nonce),
                'nonce' => substr($nonce, 0, 8) . '...'
            ]);
        }
        return false;
    }
    
    // Vérifier l'existence en session
    if (!isset($_SESSION['csp_nonces']) || !is_array($_SESSION['csp_nonces'])) {
        if (class_exists('Logger')) {
            Logger::warning('SECURITY', "Session nonces non initialisée pour validation");
        }
        return false;
    }
    
    // Vérifier l'existence du nonce
    if (!isset($_SESSION['csp_nonces'][$nonce])) {
        if (class_exists('Logger')) {
            Logger::warning('SECURITY', "Nonce non trouvé en session", [
                'nonce' => substr($nonce, 0, 8) . '...',
                'available_nonces' => count($_SESSION['csp_nonces'])
            ]);
        }
        return false;
    }
    
    // ✅ AJOUT: Vérifier l'expiration du nonce
    $timestamp = $_SESSION['csp_nonces'][$nonce];
    $maxAge = 3600; // 1 heure
    $age = time() - $timestamp;
    
    if ($age > $maxAge) {
        // Nonce expiré, le supprimer
        unset($_SESSION['csp_nonces'][$nonce]);
        
        if (class_exists('Logger')) {
            Logger::warning('SECURITY', "Nonce expiré détecté et supprimé", [
                'nonce' => substr($nonce, 0, 8) . '...',
                'age_minutes' => round($age / 60, 1),
                'max_age_minutes' => $maxAge / 60
            ]);
        }
        return false;
    }
    
    // ✅ AJOUT: Log de validation réussie (en développement uniquement)
    if (class_exists('Logger') && defined('ENVIRONMENT') && ENVIRONMENT === 'development') {
        Logger::debug('SECURITY', "Nonce validé avec succès", [
            'nonce' => substr($nonce, 0, 8) . '...',
            'age_seconds' => $age
        ]);
    }
    
    return true;
}

/**
 * ✅ AJOUT: Nettoyage manuel des nonces (utilitaire)
 */
public static function cleanupNonces($lifetime = 3600) {
    if (!isset($_SESSION['csp_nonces']) || !is_array($_SESSION['csp_nonces'])) {
        return 0;
    }
    
    $now = time();
    $cleanedCount = 0;
    
    foreach ($_SESSION['csp_nonces'] as $nonce => $timestamp) {
        if ($now - $timestamp > $lifetime) {
            unset($_SESSION['csp_nonces'][$nonce]);
            $cleanedCount++;
        }
    }
    
    if ($cleanedCount > 0 && class_exists('Logger')) {
        Logger::debug('SECURITY', "Nettoyage manuel des nonces effectué", [
            'cleaned_count' => $cleanedCount,
            'remaining_count' => count($_SESSION['csp_nonces']),
            'lifetime_minutes' => $lifetime / 60
        ]);
    }
    
    return $cleanedCount;
}

/**
 * ✅ AJOUT: Obtenir les statistiques des nonces (debug)
 */
public static function getNonceStats() {
    if (!isset($_SESSION['csp_nonces']) || !is_array($_SESSION['csp_nonces'])) {
        return [
            'total_nonces' => 0,
            'expired_nonces' => 0,
            'valid_nonces' => 0,
            'oldest_age' => 0,
            'newest_age' => 0
        ];
    }
    
    $now = time();
    $maxAge = 3600;
    $ages = [];
    $validCount = 0;
    $expiredCount = 0;
    
    foreach ($_SESSION['csp_nonces'] as $timestamp) {
        $age = $now - $timestamp;
        $ages[] = $age;
        
        if ($age > $maxAge) {
            $expiredCount++;
        } else {
            $validCount++;
        }
    }
    
    return [
        'total_nonces' => count($_SESSION['csp_nonces']),
        'expired_nonces' => $expiredCount,
        'valid_nonces' => $validCount,
        'oldest_age' => !empty($ages) ? max($ages) : 0,
        'newest_age' => !empty($ages) ? min($ages) : 0,
        'average_age' => !empty($ages) ? array_sum($ages) / count($ages) : 0
    ];
}
    


    

    
    // ================================================================================================
    // NETTOYAGE ET MAINTENANCE DES CACHES
    // ================================================================================================
    
    /**
     * Nettoie les caches si nécessaire (optimisation mémoire)
     */
    private static function cleanupCachesIfNeeded() {
        $now = time();
        
        if ($now - self::$lastCacheCleanup > self::$cacheCleanupInterval) {
            // Limiter la taille des caches de vérification
            if (count(self::$verificationCache) > 100) {
                self::$verificationCache = array_slice(self::$verificationCache, -50, null, true);
            }
            
            if (count(self::$sessionFingerprintCache) > 50) {
                self::$sessionFingerprintCache = array_slice(self::$sessionFingerprintCache, -25, null, true);
            }
            
            // Nettoyer les anciens rate limiters de session
            if (isset($_SESSION)) {
                foreach ($_SESSION as $key => $value) {
                    if (strpos($key, 'rate_limit_') === 0 && is_array($value)) {
                        if (isset($value['time']) && ($now - $value['time']) > 3600) {
                            unset($_SESSION[$key]);
                        }
                    }
                }
            }
            
            self::$lastCacheCleanup = $now;
            
            if (class_exists('Logger')) {
                Logger::debug('SECURITY', "Nettoyage des caches effectué", [
                    'verification_cache_size' => count(self::$verificationCache),
                    'fingerprint_cache_size' => count(self::$sessionFingerprintCache)
                ]);
            }
        }
    }
    
    // ================================================================================================
    // VALIDATION DE CONFIGURATION ET MÉTRIQUES
    // ================================================================================================
    
    /**
     * Validation de la configuration de sécurité
     */
    public static function validateSecurityConfiguration() {
        $issues = [];
        
        // Vérifier les constantes de sécurité
        $securityConstants = ['APP_SECRET_KEY', 'APP_ENCRYPTION_KEY', 'APP_HMAC_KEY'];
        
        foreach ($securityConstants as $constant) {
            if (!defined($constant)) {
                $issues[] = "Constante manquante: {$constant}";
            } else {
                $value = constant($constant);
                if (strlen($value) < 32) {
                    $issues[] = "Clé {$constant} trop courte (minimum 32 caractères)";
                }
                
                $weakKeys = ['default_secret_key', 'default_encryption_key', 'default_hmac_key', 'changeme', '123456'];
                if (in_array($value, $weakKeys)) {
                    $issues[] = "Clé {$constant} utilise une valeur par défaut non sécurisée";
                }
            }
        }
        
        // Vérifier les extensions PHP requises
        $requiredExtensions = ['openssl', 'pdo', 'session'];
        foreach ($requiredExtensions as $ext) {
            if (!extension_loaded($ext)) {
                $issues[] = "Extension PHP manquante: {$ext}";
            }
        }
        
        // Vérifier la configuration de session
        $sessionChecks = [
            'session.cookie_httponly' => '1',
            'session.use_strict_mode' => '1',
            'session.use_only_cookies' => '1'
        ];
        
        foreach ($sessionChecks as $directive => $expectedValue) {
            if (ini_get($directive) != $expectedValue) {
                $issues[] = "Configuration session: {$directive} devrait être {$expectedValue}";
            }
        }
        
        // Vérifier les algorithmes de chiffrement disponibles
        $preferredCiphers = ['aes-256-gcm', 'aes-256-cbc'];
        $availableCiphers = openssl_get_cipher_methods();
        $hasPreferredCipher = false;
        
        foreach ($preferredCiphers as $cipher) {
            if (in_array($cipher, $availableCiphers)) {
                $hasPreferredCipher = true;
                break;
            }
        }
        
        if (!$hasPreferredCipher) {
            $issues[] = "Aucun algorithme de chiffrement préféré disponible";
        }
        
        return empty($issues) ? true : $issues;
    }
    
    /**
     * Obtient les métriques de sécurité pour monitoring
     */
    public static function getSecurityMetrics() {
        $activeRateLimiters = 0;
        $blockedSessions = 0;
        
        // Compter les rate limiters actifs et sessions bloquées
        if (isset($_SESSION)) {
            foreach ($_SESSION as $key => $value) {
                if (strpos($key, 'rate_limit_') === 0 && is_array($value)) {
                    $activeRateLimiters++;
                    if (isset($value['blocked_until']) && $value['blocked_until'] > time()) {
                        $blockedSessions++;
                    }
                }
            }
        }
        
        return [
            'verification_cache_size' => count(self::$verificationCache),
            'fingerprint_cache_size' => count(self::$sessionFingerprintCache),
            'last_cache_cleanup' => self::$lastCacheCleanup,
            'active_rate_limiters' => $activeRateLimiters,
            'blocked_sessions' => $blockedSessions,
            'active_nonces' => isset($_SESSION['csp_nonces']) ? count($_SESSION['csp_nonces']) : 0,
            'session_fingerprint_verified' => isset($_SESSION['fingerprint']),
            'csrf_token_active' => isset($_SESSION['csrf_token']),
            'environment' => defined('ENVIRONMENT') ? ENVIRONMENT : 'unknown',
            'security_headers_available' => function_exists('header'),
            'openssl_available' => extension_loaded('openssl'),
            'session_secure' => ini_get('session.cookie_secure') == '1'
        ];
    }
    
    /**
     * Effectue un test de santé de la sécurité (mode développement uniquement)
     */
    public static function healthCheck() {
        if (!defined('ENVIRONMENT') || ENVIRONMENT !== 'development') {
            return false;
        }
        
        $results = [
            'timestamp' => date('Y-m-d H:i:s'),
            'configuration_valid' => self::validateSecurityConfiguration() === true,
            'csrf_test' => null,
            'encryption_test' => null,
            'hmac_test' => null,
            'session_test' => null
        ];
        
        try {
            // Test CSRF
            $testToken = self::generateCsrfToken();
            $results['csrf_test'] = self::validateCsrfToken($testToken);
            
            // Test chiffrement
            $testData = ['test' => 'data', 'timestamp' => time()];
            $encrypted = self::encrypt($testData);
            $decrypted = self::decrypt($encrypted);
            $results['encryption_test'] = ($decrypted === $testData);
            
            // Test HMAC
            $testHmac = self::generateHmac($testData);
            $results['hmac_test'] = self::verifyHmac($testData, $testHmac);
            
            // Test session fingerprint
            $results['session_test'] = self::checkSessionFingerprint();
            
        } catch (Exception $e) {
            $results['error'] = $e->getMessage();
        }
        
        return $results;
    }
    
    // ================================================================================================
    // MÉTHODES UTILITAIRES FINALES
    // ================================================================================================
    
    /**
     * Génère une clé aléatoire sécurisée (utilitaire)
     */
    public static function generateSecureKey($length = 32) {
        try {
            return bin2hex(random_bytes($length));
        } catch (Exception $e) {
            // Fallback moins sécurisé
            return hash('sha256', uniqid(mt_rand(), true) . microtime());
        }
    }
    
    /**
     * Vérifie si une IP est dans une liste noire (exemple basique)
     */
    public static function isIpBlacklisted($ip = null) {
        if ($ip === null) {
            $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        }
        
        // Liste basique - à adapter selon les besoins
        $blacklistedIps = [
            '192.168.1.100', // Exemple
            '10.0.0.1'       // Exemple
        ];
        
        $isBlacklisted = in_array($ip, $blacklistedIps);
        
        if ($isBlacklisted && class_exists('Logger')) {
            Logger::security('SECURITY', "IP blacklistée détectée", ['ip' => $ip]);
            self::logSecurityEvent('security_warning', 'Accès depuis IP blacklistée', ['ip' => $ip]);
        }
        
        return $isBlacklisted;
    }
    
    /**
     * Nettoyage final des ressources
     */
    public static function cleanup() {
        // Forcer le nettoyage des caches
        self::cleanupCachesIfNeeded();
        
        // Nettoyer les nonces expirés
        self::cleanupNonces();
        
        // Log des métriques finales en mode debug
        if (DEBUG_SECURITY && class_exists('Logger')) {
            $metrics = self::getSecurityMetrics();
            Logger::debug('SECURITY', "Métriques de sécurité de la session", $metrics);
        }
        
        // Vider les caches statiques
        self::$verificationCache = [];
        self::$sessionFingerprintCache = [];
    }
    
     // ================================================================================================
    // GESTION DU CACHE POUR LES AUTRES COMPOSANTS
    // ================================================================================================
    
    /**
     * Récupère une vérification mise en cache
     */
    public static function getCachedVerification($key) {
        return self::$verificationCache[$key] ?? null;
    }
    
    /**
     * Met en cache une vérification
     */
    public static function setCachedVerification($key, $value) {
        // Nettoyer si le cache devient trop volumineux
        if (count(self::$verificationCache) >= 150) {
            self::$verificationCache = array_slice(self::$verificationCache, -75, null, true);
        }
        
        self::$verificationCache[$key] = $value;
    }
    
    /**
     * Nettoie les vérifications liées au panier
     */
    public static function clearCartVerifications() {
        foreach (self::$verificationCache as $key => $value) {
            if (strpos($key, 'cart_') === 0) {
                unset(self::$verificationCache[$key]);
            }
        }
        
        if (class_exists('Logger')) {
            Logger::debug('SECURITY', "Vérifications panier nettoyées");
        }
    }
    
    /**
     * Nettoie tous les caches de tous les composants
     */
    public static function cleanupAllCaches() {
        // Nettoyage Security
        self::cleanupCachesIfNeeded();
        
        // Nettoyage Cart
        if (class_exists('Cart')) {
            Cart::clearCache();
        }
        
        // Nettoyage autres composants futurs
        if (class_exists('Database')) {
            // Database n'a pas de clearCache public, mais on pourrait l'ajouter
        }
        
        if (class_exists('Logger')) {
            Logger::debug('SECURITY', "Nettoyage global des caches effectué");
        }
    }
    
    
    
    /////////////////////////////////
    
    // ================================================================================================
    // GESTION CENTRALISÉE DES SESSIONS - NOUVEAUX AJOUTS
    // ================================================================================================
    
    /**
     * Vérifie de manière complète la sécurité de la session (empreinte + expiration)
     * MÉTHODE PRINCIPALE À APPELER DANS CHAQUE PAGE
     */
    public static function validateSession($strict = true) {
        // Vérifier si la session est active
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        // 1. Vérifier l'expiration de session
        if (!self::checkSessionExpiration()) {
            return false; // Redirection déjà effectuée dans checkSessionExpiration
        }
        
        // 2. Vérifier l'empreinte de session
        if (!self::checkSessionFingerprint($strict)) {
            if (class_exists('Logger')) {
                Logger::error('SECURITY', 'Empreinte de session invalide - hijacking détecté');
            }
            
            if (class_exists('SecureRedirect')) {
                SecureRedirect::sessionHijacking();
            }
            return false;
        }
        
        // 3. Mettre à jour l'activité
        $_SESSION['last_activity'] = time();
        
        if (class_exists('Logger')) {
            Logger::debug('SECURITY', 'Session validée avec succès');
        }
        
        return true;
    }
    
    /**
     * Vérifie l'expiration de la session avec modal automatique
     */
private static function checkSessionExpiration() {
    $now = time();
    
    // Initialiser la session si première visite
    if (!isset($_SESSION['last_activity'])) {
        $_SESSION['last_activity'] = $now;
        $_SESSION['session_start'] = $now;
        
        if (class_exists('Logger')) {
            Logger::debug('SECURITY', 'Nouvelle session initialisée');
        }
        return true;
    }
    
    $lastActivity = $_SESSION['last_activity'];
    $inactiveTime = $now - $lastActivity;
    
    // ✅ CORRECTION: Configuration des timeouts selon l'environnement
    $sessionLifetime = ENVIRONMENT === 'development' ? 
        (defined('SESSION_LIFETIME_DEV') ? SESSION_LIFETIME_DEV : SESSION_LIFETIME) : 
        (defined('SESSION_LIFETIME_PROD') ? SESSION_LIFETIME_PROD : SESSION_LIFETIME);

    // ✅ CORRECTION: Temps d'avertissement adaptatif plus strict
    $warningTime = $sessionLifetime > 360 ? $sessionLifetime - 180 : $sessionLifetime * 0.9; // 3 min ou 90%
    
    if (class_exists('Logger')) {
        Logger::debug('SECURITY', 'Vérification expiration session', [
            'last_activity' => date('Y-m-d H:i:s', $lastActivity),
            'inactive_time' => $inactiveTime,
            'session_lifetime' => $sessionLifetime,
            'expires_in' => $sessionLifetime - $inactiveTime
        ]);
    }
    
    // Session expirée
    if ($inactiveTime > $sessionLifetime) {
        $sessionDuration = $now - ($_SESSION['session_start'] ?? $now);
        
        if (class_exists('Logger')) {
            Logger::warning('SECURITY', 'Session expirée détectée', [
                'user_id' => $_SESSION['user_id'] ?? 'anonymous',
                'session_duration_minutes' => round($sessionDuration / 60, 1),
                'inactive_duration_minutes' => round($inactiveTime / 60, 1),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
        }
        
        // Journaliser l'événement de sécurité
        self::logSecurityEvent('session_expired', 'Session expirée par inactivité', [
            'inactive_time' => $inactiveTime,
            'session_duration' => $sessionDuration,
            'user_id' => $_SESSION['user_id'] ?? null
        ]);
        
        // ✅ CORRECTION: Nettoyage sécurisé complet de la session
        $isLoggedIn = isset($_SESSION['user_id']);
        $sessionData = $_SESSION; // Backup pour audit
        
        session_unset();
        session_destroy();
        
        // ✅ CORRECTION: Régénération complète
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        session_regenerate_id(true);
        
        // Message personnalisé selon le contexte
        $message = $isLoggedIn 
            ? "Votre session a expiré après " . round($inactiveTime / 60) . " minutes d'inactivité. Veuillez vous reconnecter."
            : "Votre session a expiré pour des raisons de sécurité. Vous allez être redirigé vers la page d'accueil.";
        
        // Redirection avec modal
        if (class_exists('SecureRedirect')) {
            $redirectUrl = $isLoggedIn ? 'login.php' : 'index.php';
            SecureRedirect::sessionExpired($redirectUrl, $message);
        }
        
        return false;
    }
    
    // Avertissement proche expiration (optionnel)
    if ($inactiveTime > $warningTime) {
        $remainingMinutes = round(($sessionLifetime - $inactiveTime) / 60);
        $_SESSION['session_warning'] = "Votre session expirera dans {$remainingMinutes} minute(s)";
        
        if (class_exists('Logger')) {
            Logger::info('SECURITY', "Session proche de l'expiration", [
                'remaining_minutes' => $remainingMinutes
            ]);
        }
    } else {
        // Supprimer l'avertissement s'il existe
        unset($_SESSION['session_warning']);
    }
    
    return true;
}
    
    /**
     * Définit les paramètres de session (à appeler au début de l'application)
     */
    public static function configureSession($lifetime = null) {
        if ($lifetime === null) {
            $lifetime = defined('SESSION_LIFETIME') ? SESSION_LIFETIME : 1800;
        }
        
        // Configuration des paramètres de session
        ini_set('session.gc_maxlifetime', $lifetime);
        ini_set('session.cookie_lifetime', 0); // Cookie expire à la fermeture du navigateur
        
        if (class_exists('Logger')) {
            Logger::debug('SECURITY', 'Configuration session appliquée', [
                'gc_maxlifetime' => $lifetime,
                'cookie_lifetime' => ini_get('session.cookie_lifetime')
            ]);
        }
    }
    
    /**
     * Test manuel de session expirée (développement uniquement)
     */
    public static function testSessionExpiration() {
        if (!defined('ENVIRONMENT') || ENVIRONMENT !== 'development') {
            return false;
        }
        
        if (class_exists('Logger')) {
            Logger::info('SECURITY', 'Test manuel de session expirée');
        }
        
        if (class_exists('SecureRedirect')) {
            SecureRedirect::sessionExpired('index.php', 'Test de session expirée (mode développement)');
        }
        
        return true;
    }
    
    /**
     * Récupère les informations de session pour debugging
     */
    public static function getSessionInfo() {
        if (!isset($_SESSION['last_activity'])) {
            return ['status' => 'not_initialized'];
        }
        
        $now = time();
        $lastActivity = $_SESSION['last_activity'];
        $sessionLifetime = defined('SESSION_LIFETIME') ? SESSION_LIFETIME : 1800;
        $inactiveTime = $now - $lastActivity;
        $remainingTime = $sessionLifetime - $inactiveTime;
        
        return [
            'status' => 'active',
            'session_id' => session_id(),
            'last_activity' => $lastActivity,
            'last_activity_formatted' => date('Y-m-d H:i:s', $lastActivity),
            'current_time' => $now,
            'inactive_time' => $inactiveTime,
            'inactive_minutes' => round($inactiveTime / 60, 1),
            'session_lifetime' => $sessionLifetime,
            'remaining_time' => $remainingTime,
            'remaining_minutes' => round($remainingTime / 60, 1),
            'is_near_expiry' => $remainingTime < 300, // 5 minutes
            'user_id' => $_SESSION['user_id'] ?? null,
            'session_warning' => $_SESSION['session_warning'] ?? null
        ];
    }
    
    
    
    
    
            /**
     * Journalise un événement de sécurité de façon centralisée
     */
    public static function logSecurityEvent($eventType, $message, $context = []) {
        if (class_exists('Logger')) {
            Logger::security('SECURITY', $message, array_merge(['event_type' => $eventType], $context));
        }
    }
}
    
    
    /////////////////////////
    


// ================================================================================================
// INITIALISATION AUTOMATIQUE ET NETTOYAGE
// ================================================================================================

// Enregistrer le nettoyage automatique des caches en fin de script
register_shutdown_function(function() {
    Security::cleanup();
});
    

    
<?php
// ================================================================================================
// CONFIGURATION PRINCIPALE AVEC GESTION D'ERREUR CENTRALISÉE
// ================================================================================================

/**
 * Gestion centralisée des erreurs critiques bloquantes
 */
function handleCriticalError($title, $body, $logMessage = '', $httpCode = 503, $retryAfter = 1800) {
    error_log($logMessage ?: $body);
    if (!headers_sent()) {
        header("HTTP/1.1 $httpCode Service Unavailable");
        header('Content-Type: text/html; charset=UTF-8');
        header('Retry-After: ' . $retryAfter);
    }
    echo "<!DOCTYPE html>
    <html><head><title>$title</title></head><body>
    <h1>⚠️ $title</h1>
    <p>$body</p>
    </body></html>";
    exit(1);
}

// ================================================================================================
// 1. VÉRIFICATIONS PRÉLIMINAIRES CRITIQUES
// ================================================================================================

/**
 * Vérification de la version PHP (critère bloquant)
 */
$requiredPhpVersion = '8.0.0';
$currentPhpVersion = PHP_VERSION;

if (version_compare($currentPhpVersion, $requiredPhpVersion) < 0) {
    handleCriticalError(
        "Version PHP Incompatible",
        "Cette application nécessite PHP {$requiredPhpVersion} ou supérieur.<br>Version détectée : PHP {$currentPhpVersion}<br>Veuillez mettre à jour votre environnement PHP.",
        "CRITICAL: PHP version incompatible - Required: {$requiredPhpVersion}, Current: {$currentPhpVersion}",
        503,
        3600
    );
}

// ================================================================================================
// 2. CHARGEMENT DE LA CONFIGURATION LOCALE SÉCURISÉE
// ================================================================================================

/**
 * Recherche et chargement du fichier de configuration sensible
 */
$configPaths = [
    dirname(dirname(__DIR__)) . '/config.local.php',  // Emplacement recommandé (hors web)
    __DIR__ . '/config.local.php',                    // Fallback 1
    dirname(__DIR__) . '/config.local.php',           // Fallback 2
    $_SERVER['DOCUMENT_ROOT'] . '/../config.local.php' // Fallback 3
];

$configLoaded = false;
$configPath = null;

foreach ($configPaths as $path) {
    if (file_exists($path) && is_readable($path)) {
        try {
            require_once $path;
            $configPath = $path;
            $configLoaded = true;
            break;
        } catch (ParseError $e) {
            error_log("CONFIG_PARSE_ERROR: Syntax error in {$path} - " . $e->getMessage());
            continue;
        } catch (Error $e) {
            error_log("CONFIG_FATAL_ERROR: Fatal error in {$path} - " . $e->getMessage());
            continue;
        }
    }
}

// Gestion de l'échec de chargement de configuration
if (!$configLoaded) {
    handleCriticalError(
        "Configuration Manquante",
        "Le fichier de configuration de l'application est manquant ou illisible.<br>Veuillez contacter l'administrateur système.",
        "CONFIG_MISSING: No valid configuration file found in paths: " . implode(', ', $configPaths),
        503,
        1800
    );
}

// ================================================================================================
// 3. VALIDATION DES CONSTANTES DE SÉCURITÉ CRITIQUES
// ================================================================================================

/**
 * Constantes obligatoires pour le fonctionnement sécurisé
 */
$requiredConstants = [
    'DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_CHARSET',
    'APP_SECRET_KEY', 'APP_ENCRYPTION_KEY', 'APP_HMAC_KEY'
];

$missingConstants = [];
$weakSecurityKeys = [];

foreach ($requiredConstants as $constant) {
    if (!defined($constant)) {
        $missingConstants[] = $constant;
    } else {
        // Validation renforcée des clés de sécurité
        if (in_array($constant, ['APP_SECRET_KEY', 'APP_ENCRYPTION_KEY', 'APP_HMAC_KEY'])) {
            $value = constant($constant);
            
            // ✅ CORRECTION: Validation stricte de longueur
            if (strlen($value) < 64) {
                $weakSecurityKeys[] = $constant . ' (longueur < 64 caractères)';
            }
            
            // ✅ CORRECTION: Liste étendue de clés faibles
            $weakKeys = [
                'default_secret_key', 'default_encryption_key', 'default_hmac_key', 
                'changeme', '123456', 'secret', 'password', 'admin', 'test',
                'development_key', 'dev_key', 'temp_key', 'example_key',
                str_repeat('a', 64), str_repeat('1', 64), str_repeat('0', 64)
            ];
            
            if (in_array(strtolower($value), array_map('strtolower', $weakKeys))) {
                $weakSecurityKeys[] = $constant . ' (clé prédéfinie faible)';
            }
            
            // ✅ AJOUT: Validation entropie
            if (strlen(count_chars($value, 3)) < 10) {
                $weakSecurityKeys[] = $constant . ' (entropie insuffisante)';
            }
            
            // ✅ AJOUT: Validation pattern répétitif
            if (preg_match('/(.)\1{5,}/', $value)) {
                $weakSecurityKeys[] = $constant . ' (pattern répétitif détecté)';
            }
        }
    }
}

// ✅ CORRECTION: Traitement strict des clés faibles
if (!empty($weakSecurityKeys)) {
    handleCriticalError(
        "Clés de Sécurité Faibles",
        "Des clés de sécurité faibles ont été détectées.<br>Veuillez les remplacer par des clés robustes.",
        "CRITICAL: Weak security keys detected: " . implode(', ', $weakSecurityKeys),
        503,
        3600
    );
}

// Gestion des constantes manquantes (bloquant)
if (!empty($missingConstants)) {
    handleCriticalError(
        "Configuration Incomplète",
        "Des constantes requises sont manquantes dans la configuration.<br>Veuillez vérifier votre fichier config.local.php.",
        "CONFIG_INCOMPLETE: Missing required constants: " . implode(', ', $missingConstants),
        503,
        1800
    );
}

// Avertissement pour les clés faibles (non bloquant mais logué)
if (!empty($weakSecurityKeys)) {
    error_log("CONFIG_SECURITY_WARNING: Weak security keys detected: " . implode(', ', $weakSecurityKeys));
}

// ================================================================================================
// 4. DÉFINITION DES CONSTANTES D'ENVIRONNEMENT ET DE SÉCURITÉ
// ================================================================================================

/**
 * Environnement d'exécution avec fallback sécurisé
 */
if (!defined('ENVIRONMENT')) {
    define('ENVIRONMENT', 'production'); // Fallback sécurisé (plus restrictif)
}

/**
 * Constantes de sécurité applicative
 */
if (!defined('SECURE_ACCESS')) {
    define('SECURE_ACCESS', true);
}

// Constantes de contrôle CSRF renforcées
if (!defined('CSRF_TOKEN_EXPIRATION')) {
    define('CSRF_TOKEN_EXPIRATION', 1800); // 30 minutes - synchronisé avec session
}

if (!defined('CSRF_TOKEN_LENGTH')) {
    define('CSRF_TOKEN_LENGTH', 64); // Longueur uniforme dans tout le système
}

// ✅ AJOUT: Politique stricte de génération de tokens
if (!defined('REQUIRE_SECURE_RANDOM')) {
    define('REQUIRE_SECURE_RANDOM', true); // Refuser les fallbacks non sécurisés
}

// ✅ AJOUT: Validation de l'environnement cryptographique
if (!function_exists('random_bytes')) {
    handleCriticalError(
        "Environnement Non Sécurisé",
        "L'environnement ne supporte pas la génération cryptographique sécurisée.<br>Fonction random_bytes() manquante.",
        "CRITICAL: random_bytes() not available - cryptographically unsafe environment",
        503,
        0
    );
}

// ✅ NOUVEAU CODE - Sodium optionnel avec fallback
$requiredSecurityExtensions = ['openssl']; // ← SODIUM RETIRÉ DES OBLIGATOIRES

// Vérification Sodium avec fallback gracieux
$hasSodium = extension_loaded('sodium');
if (!$hasSodium) {
    error_log("WARNING: Extension Sodium non disponible - Fallback vers OpenSSL");
    define('SODIUM_AVAILABLE', false);
    
    // Vérifier que OpenSSL peut compenser
    if (!extension_loaded('openssl')) {
        handleCriticalError(
            "Aucune Extension Cryptographique",
            "Ni Sodium ni OpenSSL ne sont disponibles."
        );
    }
} else {
    define('SODIUM_AVAILABLE', true);
}

// Constantes de chiffrement
if (!defined('ENCRYPTION_CIPHER')) {
    define('ENCRYPTION_CIPHER', 'aes-256-gcm');
}
if (!defined('ENCRYPTION_TAG_LENGTH')) {
    define('ENCRYPTION_TAG_LENGTH', 16);
}

if (!defined('CART_LIFETIME')) {
    define('CART_LIFETIME', 86400); // 24 heures
}

// ✅ NOUVELLE LIGNE À AJOUTER :
if (!defined('REGENERATE_SESSION_ON_CART_ACTIONS')) {
    define('REGENERATE_SESSION_ON_CART_ACTIONS', true); // Désactiver régénération session panier
}

// Constantes de gestion des sessions
// Constantes de gestion des sessions
if (!defined('SESSION_LIFETIME')) {
    define('SESSION_LIFETIME', 1800); // 30 minutes par défaut
}

// Configuration selon l'environnement
switch (ENVIRONMENT) {
    case 'development':
        if (!defined('SESSION_LIFETIME_DEV')) {
            define('SESSION_LIFETIME_DEV', 1800); // 30 secondes pour test en dev
        }
        break;
    case 'production':
        if (!defined('SESSION_LIFETIME_PROD')) {
            define('SESSION_LIFETIME_PROD', 1800); // 30 minutes en production
        }
        break;
}



















if (!defined('MAX_CART_ITEMS')) {
    define('MAX_CART_ITEMS', 50);
}

// Constantes de rate limiting
if (!defined('RATE_LIMIT')) {
    define('RATE_LIMIT', 60); // Requêtes par minute
}
if (!defined('RATE_LIMIT_TIMEOUT')) {
    define('RATE_LIMIT_TIMEOUT', 300); // 5 minutes de blocage
}

// Constantes de base de données
if (!defined('CART_DB_CLEANUP_INTERVAL')) {
    define('CART_DB_CLEANUP_INTERVAL', 86400); // 24 heures
}
if (!defined('CART_DB_ABANDONED_DAYS')) {
    define('CART_DB_ABANDONED_DAYS', 30);
}
if (!defined('CART_DB_DELETE_DAYS')) {
    define('CART_DB_DELETE_DAYS', 90);
}

// Constante de sécurité pour les tâches cron
if (!defined('CRON_SECURITY_TOKEN')) {
    define('CRON_SECURITY_TOKEN', hash('sha256', APP_SECRET_KEY . 'cron_salt'));
}

// Nom du site
if (!defined('SITE_NAME')) {
    define('SITE_NAME', 'E-commerce');
}

// ================================================================================================
// 5. CONFIGURATION DE LA JOURNALISATION
// ================================================================================================

/**
 * Configuration du système de logs selon l'environnement
 */
if (!defined('ENABLE_LOGGING')) {
    define('ENABLE_LOGGING', true);
}

if (!defined('LOG_DIR')) {
    define('LOG_DIR', __DIR__ . '/logs');
}

if (!defined('LOGGING_MODE')) {
    define('LOGGING_MODE', 'unified');
}

if (!defined('UNIFIED_LOG_FILE')) {
    define('UNIFIED_LOG_FILE', LOG_DIR . '/application.log');
}

// Rediriger tous les logs vers le fichier unifié en mode unifié
if (LOGGING_MODE === 'unified') {
    if (!defined('SECURITY_LOG_FILE')) {
        define('SECURITY_LOG_FILE', UNIFIED_LOG_FILE);
    }
    if (!defined('ERROR_LOG_FILE')) {
        define('ERROR_LOG_FILE', UNIFIED_LOG_FILE);
    }
    if (!defined('CART_LOG_FILE')) {
        define('CART_LOG_FILE', UNIFIED_LOG_FILE);
    }
    if (!defined('ACCESS_LOG_FILE')) {
        define('ACCESS_LOG_FILE', UNIFIED_LOG_FILE);
    }
}

// Taille maximale des fichiers de log
if (!defined('MAX_LOG_SIZE')) {
    define('MAX_LOG_SIZE', 10 * 1024 * 1024); // 10 Mo
}

// ================================================================================================
// 6. CRÉATION SÉCURISÉE DU RÉPERTOIRE DE LOGS
// ================================================================================================

/**
 * Création et sécurisation du répertoire de logs
 */
if (ENABLE_LOGGING && !is_dir(LOG_DIR)) {
    if (!mkdir(LOG_DIR, 0755, true)) {
        handleCriticalError(
            "Erreur système",
            "Impossible de créer le répertoire de logs.<br>Vérifiez les droits d'écriture.",
            "LOG_DIR_CREATION_ERROR: Failed to create log dir " . LOG_DIR,
            500,
            0
        );
    }
    // Créer le fichier .htaccess de protection
    $htaccessContent = "# Protection du répertoire de logs\n";
    $htaccessContent .= "Order deny,allow\n";
    $htaccessContent .= "Deny from all\n";
    $htaccessContent .= "<Files ~ \"^\.\">\n";
    $htaccessContent .= "    Order allow,deny\n";
    $htaccessContent .= "    Deny from all\n";
    $htaccessContent .= "</Files>\n";
    file_put_contents(LOG_DIR . '/.htaccess', $htaccessContent);

    // Créer un fichier index.php vide pour masquer le contenu
    file_put_contents(LOG_DIR . '/index.php', '<?php /* Répertoire protégé */ ?>');
}

// ================================================================================================
// 7. CONFIGURATION DES SESSIONS SÉCURISÉES
// ================================================================================================

/**
 * Configuration sécurisée des sessions selon l'environnement
 */
$sessionConfig = [
    'cookie_httponly' => 1,
    'cookie_samesite' => 'Lax',
    'use_strict_mode' => 1,  // ✅ CORRECTION: Active la protection contre la fixation
    'use_only_cookies' => 1,
    'use_trans_sid' => 0,
    'sid_length' => 48,
    'sid_bits_per_character' => 6,
    'gc_maxlifetime' => ENVIRONMENT === 'development' ? SESSION_LIFETIME_DEV : SESSION_LIFETIME,
    'cookie_lifetime' => 0,
    'cache_limiter' => 'nocache',
    'hash_function' => 'sha256',
    'cookie_domain' => '', // Auto-détection sécurisée
    'cookie_path' => '/',  // Chemin racine
    'sid_bits_per_character' => 6,
    'entropy_length' => 32, // ✅ AJOUT: Entropie renforcée
    'entropy_file' => '/dev/urandom' // ✅ AJOUT: Source d'entropie sécurisée
];

// Configuration spécifique selon l'environnement
switch (ENVIRONMENT) {
    case 'production':
        $sessionConfig['cookie_secure'] = 1; // HTTPS obligatoire
        break;
    case 'development':
    case 'testing':
    default:
        $sessionConfig['cookie_secure'] = 0; // HTTP autorisé pour dev
        break;
}

// Appliquer la configuration de session
foreach ($sessionConfig as $directive => $value) {
    ini_set("session.{$directive}", $value);
}

// Configuration d'entropie pour Linux
if (PHP_OS_FAMILY === 'Linux' && file_exists('/dev/urandom')) {
    ini_set('session.entropy_file', '/dev/urandom');
    ini_set('session.entropy_length', 32);
}

// ================================================================================================
// 8. CONFIGURATION DES CONSTANTES DE DEBUG PAR ENVIRONNEMENT
// ================================================================================================

/**
 * Constantes de debug optimisées selon l'environnement
 */
$debugConfig = [
    'production' => [
        'DEBUG_CART' => false,
        'DEBUG_DATABASE' => false,
        'DEBUG_SECURITY' => false,
        'DEBUG_CART_CONTROLLER' => false,
        'DEBUG_CONFIG' => false
    ],
    'testing' => [
        'DEBUG_CART' => false,
        'DEBUG_DATABASE' => true,  // Utile pour les tests
        'DEBUG_SECURITY' => true,  // Utile pour les tests
        'DEBUG_CART_CONTROLLER' => false,
        'DEBUG_CONFIG' => false
    ],
    'development' => [
        'DEBUG_CART' => true,
        'DEBUG_DATABASE' => true,
        'DEBUG_SECURITY' => true,
        'DEBUG_CART_CONTROLLER' => false, // Trop verbeux
        'DEBUG_CONFIG' => false           // Trop verbeux
    ]
];

// Appliquer la configuration de debug
$envDebugConfig = $debugConfig[ENVIRONMENT] ?? $debugConfig['production'];
foreach ($envDebugConfig as $constant => $value) {
    if (!defined($constant)) {
        define($constant, $value);
    }
}

// ================================================================================================
// 9. CONFIGURATION PHP SELON L'ENVIRONNEMENT
// ================================================================================================

/**
 * Configuration d'affichage d'erreurs PHP selon l'environnement
 */
switch (ENVIRONMENT) {
    case 'development':
        error_reporting(E_ALL);
        ini_set('display_errors', 1);
        ini_set('display_startup_errors', 1);
        ini_set('log_errors', 1);
        break;
    case 'testing':
        error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT);
        ini_set('display_errors', 0);
        ini_set('display_startup_errors', 0);
        ini_set('log_errors', 1);
        break;
    case 'production':
    default:
        error_reporting(E_ERROR | E_WARNING | E_PARSE);
        ini_set('display_errors', 0);
        ini_set('display_startup_errors', 0);
        ini_set('log_errors', 1);
        break;
}

// ================================================================================================
// 10. INITIALISATION DIFFÉRÉE DES DÉPENDANCES (RÉSOUT LES CYCLES)
// ================================================================================================

/**
 * Classe statique pour gérer l'initialisation différée des dépendances
 */
class DependencyManager {
    private static $initialized = false;
    private static $initCallbacks = [];
    
    /**
     * Ajoute un callback d'initialisation à exécuter plus tard
     */
    public static function addInitCallback($callback, $priority = 10) {
        if (!self::$initialized) {
            self::$initCallbacks[] = ['callback' => $callback, 'priority' => $priority];
        }
    }
    
    /**
     * Exécute tous les callbacks d'initialisation
     */
    public static function initialize() {
        if (self::$initialized) {
            return true;
        }
        
        // Trier par priorité
        usort(self::$initCallbacks, function($a, $b) {
            return $a['priority'] <=> $b['priority'];
        });
        
        // Exécuter les callbacks
        foreach (self::$initCallbacks as $item) {
            try {
                call_user_func($item['callback']);
            } catch (Exception $e) {
                error_log("DEPENDENCY_INIT_ERROR: " . $e->getMessage());
            }
        }
        
        self::$initialized = true;
        self::$initCallbacks = []; // Libérer la mémoire
        
        return true;
    }
    
    /**
     * Vérifie si l'initialisation a été faite
     */
    public static function isInitialized() {
        return self::$initialized;
    }
}



function initializeDependencies() {
    static $initialized = false;
    
    // ✅ CORRECTION: Prévention de l'initialisation multiple
    if ($initialized) {
        return true;
    }
    
    try {
        // ✅ CORRECTION: Validation préalable des classes
        $requiredClasses = ['Database', 'Security', 'Logger'];
        foreach ($requiredClasses as $class) {
            if (!class_exists($class)) {
                throw new Exception("Classe critique manquante: {$class}");
            }
        }
        
   // 1. Initialiser Database en premier
$db = Database::getInstance();

// 2. ✅ SUPPRIMER cette ligne qui cause une erreur fatale
// Database::setLogCallback(function($type, $message, $data) {
//     if (class_exists('Logger') && $type !== 'dependency_init') {
//         Logger::log('DATABASE', $message, $type, $data);
//     }
// });


        
        // 3. Injecter Database dans Security
        Security::setDatabaseInstance($db);
        
        // 4. ✅ CORRECTION: Configuration des sessions centralisée et sécurisée
        if (class_exists('Security')) {
            $sessionLifetime = ENVIRONMENT === 'development' ? 
                (defined('SESSION_LIFETIME_DEV') ? SESSION_LIFETIME_DEV : SESSION_LIFETIME) : 
                (defined('SESSION_LIFETIME_PROD') ? SESSION_LIFETIME_PROD : SESSION_LIFETIME);
                
            Security::configureSession($sessionLifetime);
            
            // ✅ AJOUT: Validation de l'intégrité du système
            $configCheck = Security::validateSecurityConfiguration();
            if ($configCheck !== true) {
                throw new Exception("Configuration de sécurité invalide: " . json_encode($configCheck));
            }
        }
        
        // ✅ CORRECTION: Marquer comme initialisé AVANT le log
        $initialized = true;
        
        // 5. Log de fin d'initialisation
        if (class_exists('Logger')) {
            Logger::info('CONFIG', 'Dépendances initialisées avec succès', [
                'environment' => ENVIRONMENT,
                'config_file' => basename($GLOBALS['configPath'] ?? 'unknown'),
                'session_lifetime' => $sessionLifetime ?? 'default',
                'security_validated' => true
            ]);
        }
        
        return true;
        
    } catch (Exception $e) {
        error_log("CRITICAL_DEPENDENCY_ERROR: " . $e->getMessage());
        
        // ✅ AJOUT: Gestion d'erreur plus robuste
        if (function_exists('handleCriticalError')) {
            handleCriticalError(
                "Erreur d'Initialisation",
                "Impossible d'initialiser les composants de sécurité.",
                "DEPENDENCY_INIT_FAILED: " . $e->getMessage(),
                503,
                1800
            );
        }
        
        return false;
    }
}

// Enregistrer l'initialisation différée
if (class_exists('DependencyManager')) {
    DependencyManager::addInitCallback('initializeDependencies', 1);
}

// ================================================================================================
// 11. FONCTIONS UTILITAIRES DE CONFIGURATION
// ================================================================================================

/**
 * Génère une nouvelle clé aléatoire sécurisée
 * Utile pour régénérer les clés de sécurité
 */
function generateSecureKey($length = 32) {
    try {
        return bin2hex(random_bytes($length));
    } catch (Exception $e) {
        // Fallback moins sécurisé mais fonctionnel
        return hash('sha256', uniqid(mt_rand(), true) . microtime());
    }
}

// ✅ SUPPRIMÉ : Section debug qui s'affichait
/*
if (ENVIRONMENT === 'development' && class_exists('Logger')) {
    Logger::debug('CONFIG', 'Exemples de nouvelles clés sécurisées', [
        'example_secret_key' => generateSecureKey(32),
        'example_encryption_key' => generateSecureKey(32),
        'example_hmac_key' => generateSecureKey(32)
    ]);
}
*/

// ================================================================================================
// 12. FINALISATION
// ================================================================================================

// ✅ CONSERVÉ : Log de fin de chargement (Logger uniquement)
if (class_exists('Logger')) {
    Logger::info('CONFIG', 'Configuration chargée avec succès', [
        'environment' => ENVIRONMENT,
        'php_version' => PHP_VERSION,
        'config_source' => $configPath ?? 'unknown',
        'logging_enabled' => ENABLE_LOGGING,
        'session_lifetime' => ini_get('session.gc_maxlifetime')
    ]);
}

// Marquer que la configuration est chargée
if (!defined('CONFIG_LOADED')) {
    define('CONFIG_LOADED', true);
}

// Note : L'initialisation des dépendances sera faite automatiquement
// quand toutes les classes seront chargées via DependencyManager::initialize()

// ================================================================================================
// NETTOYAGE CENTRALISÉ EN FIN DE SCRIPT
// ================================================================================================

/**
 * Enregistrer le nettoyage centralisé de tous les composants
 */
register_shutdown_function(function() {
    try {
        if (class_exists('Security')) {
            Security::cleanupAllCaches();
        }
        
        // Forcer le vidage du buffer Logger
        if (class_exists('Logger')) {
            Logger::flushBuffer();
        }
    } catch (Exception $e) {
        error_log("SHUTDOWN_CLEANUP_ERROR: " . $e->getMessage());
    }
});







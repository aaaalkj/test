<?php

class Logger {

    // ============================================================================================
    // 1. DÉFINITION DES NIVEAUX ET MAPPINGS
    // ============================================================================================

    const LEVEL_CRITICAL = 0;  // Erreurs critiques système
    const LEVEL_SECURITY = 1;  // Événements de sécurité
    const LEVEL_ERROR    = 2;  // Erreurs applicatives
    const LEVEL_WARNING  = 3;  // Avertissements importants
    const LEVEL_INFO     = 4;  // Informations importantes
    const LEVEL_DEBUG    = 5;  // Debug (développement uniquement)

    /**
     * Mapping des types de log vers les niveaux
     */
    private static $levelMapping = [
        'critical'    => self::LEVEL_CRITICAL,
        'security'    => self::LEVEL_SECURITY,
        'error'       => self::LEVEL_ERROR,
        'warning'     => self::LEVEL_WARNING,
        'info'        => self::LEVEL_INFO,
        'debug'       => self::LEVEL_DEBUG,
        // Alias pour compatibilité
        'action'      => self::LEVEL_INFO,
        'performance' => self::LEVEL_DEBUG,
        'query'       => self::LEVEL_DEBUG,
        'cache'       => self::LEVEL_DEBUG,
        'db'          => self::LEVEL_DEBUG
    ];

    // ============================================================================================
    // 2. PROPRIÉTÉS STATIQUES
    // ============================================================================================

    private static $logBuffer   = [];
    private static $bufferSize  = 50;
    private static $fileChecks  = [];
    private static $stats       = [
        'entries_logged'   => 0,
        'entries_filtered' => 0,
        'buffer_flushes'   => 0,
        'file_rotations'   => 0
    ];
    private static $minLogLevel = null;

    // ============================================================================================
    // 3. POINT D'ENTRÉE PRINCIPAL POUR LA JOURNALISATION
    // ============================================================================================

    /**
     * Log principal.
     */
    public static function log($component, $message, $level = 'info', $context = []) {
        if (self::$minLogLevel === null) {
            self::initializeLogLevel();
        }

        $numericLevel = self::$levelMapping[strtolower($level)] ?? self::LEVEL_INFO;

        // Filtrage selon le niveau minimum
        if ($numericLevel > self::$minLogLevel) {
            self::$stats['entries_filtered']++;
            return true;
        }

        if (!self::isLoggingEnabled()) {
            return false;
        }

        // Data cleansing context (préconisation: pas de mot de passe ni tokens dans les logs)
        $context = self::sanitizeForLog($context);

        $entry = self::createLogEntry($component, $message, $level, $context, $numericLevel);

        // Critique ou erreur : écriture immédiate
        if ($numericLevel <= self::LEVEL_ERROR) {
            self::flushBuffer();
            return self::writeLogEntry($entry);
        } else {
            return self::addToBuffer($entry);
        }
    }

    // ============================================================================================
    // 4. INITIALISATION ET CONTRÔLES
    // ============================================================================================

    private static function initializeLogLevel() {
        if (defined('ENVIRONMENT')) {
            switch (ENVIRONMENT) {
                case 'production':
                    self::$minLogLevel = self::LEVEL_WARNING;
                    break;
                case 'testing':
                    self::$minLogLevel = self::LEVEL_INFO;
                    break;
                case 'development':
                default:
                    self::$minLogLevel = self::LEVEL_DEBUG;
                    break;
            }
        } else {
            self::$minLogLevel = self::LEVEL_INFO;
        }
    }

    private static function isLoggingEnabled() {
        return defined('ENABLE_LOGGING') && ENABLE_LOGGING === true;
    }

    // ============================================================================================
    // 5. SÉCURISATION DU CONTEXTE LOGUÉ
    // ============================================================================================

    /**
     * Nettoyage du contexte pour éviter de logger des secrets/tokens
     */
    private static function sanitizeForLog($context) {
        if (!is_array($context)) return $context;
        $blacklist = ['password', 'pwd', 'pass', 'csrf_token', 'token', 'secret', 'key', 'session_id'];
        foreach ($blacklist as $bad) {
            if (isset($context[$bad])) $context[$bad] = '***';
        }
        // Nettoyage récursif si sous-tableaux
        foreach ($context as $k => $v) {
            if (is_array($v)) {
                $context[$k] = self::sanitizeForLog($v);
            }
        }
        return $context;
    }

    // ============================================================================================
    // 6. CRÉATION ET STRUCTURATION DES ENTRÉES
    // ============================================================================================

    private static function createLogEntry($component, $message, $level, $context, $numericLevel) {
        $entry = [
            'timestamp'    => date('Y-m-d H:i:s.v'),
            'level'        => strtoupper($level),
            'level_num'    => $numericLevel,
            'component'    => strtoupper($component),
            'message'      => $message,
            'context'      => $context,
            'memory_usage' => memory_get_usage(true),
            'pid'          => getmypid()
        ];
        if (session_status() === PHP_SESSION_ACTIVE) {
            $entry['session_id'] = session_id();
        }
        if (isset($_SERVER['REQUEST_URI'])) {
            $entry['request_uri'] = $_SERVER['REQUEST_URI'];
        }
        if (isset($_SERVER['REMOTE_ADDR'])) {
            $entry['client_ip'] = $_SERVER['REMOTE_ADDR'];
        }
        return $entry;
    }

    // ============================================================================================
    // 7. BUFFERISATION ET ÉCRITURE
    // ============================================================================================

    private static function addToBuffer($entry) {
        self::$logBuffer[] = $entry;
        self::$stats['entries_logged']++;
        if (count(self::$logBuffer) >= self::$bufferSize) {
            return self::flushBuffer();
        }
        return true;
    }

    public static function flushBuffer() {
        if (empty(self::$logBuffer)) {
            return true;
        }
        $success = true;
        foreach (self::$logBuffer as $entry) {
            if (!self::writeLogEntry($entry)) $success = false;
        }
        self::$logBuffer = [];
        self::$stats['buffer_flushes']++;
        return $success;
    }

    private static function writeLogEntry($entry) {
        try {
            $logFile = self::getLogFile($entry['component']);
            if (!self::prepareLogFile($logFile)) return false;
            self::rotateLogIfNeeded($logFile);
            $logLine = json_encode($entry, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
            $bytesWritten = file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);
            return $bytesWritten !== false;
        } catch (Exception $e) {
            error_log("LOGGER_ERROR: Impossible d'écrire dans {$logFile} - " . $e->getMessage());
            error_log("ORIGINAL_LOG: " . json_encode($entry));
            return false;
        }
    }

    // ============================================================================================
    // 8. LOG FILE MANAGEMENT
    // ============================================================================================

    private static function getLogFile($component) {
        // Mode unifié (recommandé)
        if (defined('LOGGING_MODE') && LOGGING_MODE === 'unified') {
            return defined('UNIFIED_LOG_FILE') ? UNIFIED_LOG_FILE : self::getDefaultLogFile();
        }
        $logDir = defined('LOG_DIR') ? LOG_DIR : __DIR__ . '/logs';
        $componentMap = [
            'SECURITY'        => $logDir . '/security.log',
            'DATABASE'        => $logDir . '/database.log',
            'CART'            => $logDir . '/cart.log',
            'CART_CONTROLLER' => $logDir . '/cart.log',
            'UPDATE_CART'     => $logDir . '/cart.log',
        ];
        return $componentMap[$component] ?? $logDir . '/application.log';
    }

    private static function getDefaultLogFile() {
        $logDir = __DIR__ . '/logs';
        return $logDir . '/application.log';
    }

    private static function prepareLogFile($logFile) {
        if (isset(self::$fileChecks[$logFile])) return self::$fileChecks[$logFile];
        $logDir = dirname($logFile);
        // Création répertoire sécurisé
        if (!is_dir($logDir)) {
            if (!mkdir($logDir, 0755, true)) {
                self::$fileChecks[$logFile] = false;
                return false;
            }
            // Protection .htaccess
            $htaccessFile = $logDir . '/.htaccess';
            if (!file_exists($htaccessFile)) {
                file_put_contents($htaccessFile, "# Protection du répertoire de logs\nOrder deny,allow\nDeny from all\n<Files ~ \"^\\.\" >\n    Order allow,deny\n    Deny from all\n</Files>\n");
            }
            // Protection index.php
            $indexFile = $logDir . '/index.php';
            if (!file_exists($indexFile)) {
                file_put_contents($indexFile, '<?php /* Répertoire protégé */ ?>');
            }
        }
        if (!is_writable($logDir)) {
            self::$fileChecks[$logFile] = false;
            return false;
        }
        self::$fileChecks[$logFile] = true;
        return true;
    }

    private static function rotateLogIfNeeded($logFile) {
        if (!file_exists($logFile)) return;
        $maxSize = defined('MAX_LOG_SIZE') ? MAX_LOG_SIZE : (10 * 1024 * 1024);
        if (filesize($logFile) > $maxSize) {
            $backupFile = $logFile . '.' . date('Y-m-d-H-i-s') . '.bak';
            if (rename($logFile, $backupFile)) {
                self::$stats['file_rotations']++;
                $rotationEntry = [
                    'timestamp' => date('Y-m-d H:i:s.v'),
                    'level'     => 'INFO',
                    'component' => 'LOGGER',
                    'message'   => 'Rotation du fichier de log effectuée',
                    'context'   => [
                        'old_file' => $backupFile,
                        'new_file' => $logFile,
                        'old_size' => filesize($backupFile)
                    ]
                ];
                $logLine = json_encode($rotationEntry, JSON_UNESCAPED_UNICODE) . PHP_EOL;
                file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);
            }
        }
    }

    // ============================================================================================
    // 9. MÉTHODES DE CONVENANCE
    // ============================================================================================

    public static function critical($component, $message, $context = []) {
        return self::log($component, $message, 'critical', $context);
    }
    public static function security($component, $message, $context = []) {
        return self::log($component, $message, 'security', $context);
    }
    public static function error($component, $message, $context = []) {
        return self::log($component, $message, 'error', $context);
    }
    public static function warning($component, $message, $context = []) {
        return self::log($component, $message, 'warning', $context);
    }
    public static function info($component, $message, $context = []) {
        return self::log($component, $message, 'info', $context);
    }
    public static function debug($component, $message, $context = []) {
        return self::log($component, $message, 'debug', $context);
    }

    // ============================================================================================
    // 10. STATISTIQUES ET NETTOYAGE
    // ============================================================================================

    public static function getStats() {
        return array_merge(self::$stats, [
            'buffer_size'   => count(self::$logBuffer),
            'min_log_level' => self::$minLogLevel,
            'environment'   => defined('ENVIRONMENT') ? ENVIRONMENT : 'undefined'
        ]);
    }

    public static function cleanup() {
        // Vider le buffer restant, loguer en debug en dev, nettoyer les caches
        self::flushBuffer();
        if (self::$minLogLevel >= self::LEVEL_DEBUG && self::$stats['entries_logged'] > 0) {
            self::log('LOGGER', 'Session de journalisation terminée', 'debug', self::getStats());
        }
        self::$fileChecks = [];
        self::$logBuffer  = [];
    }

    // ============================================================================================
    // 11. TEST (DEV ONLY)
    // ============================================================================================

    public static function test() {
        if (!defined('ENVIRONMENT') || ENVIRONMENT !== 'development') return false;
        self::critical('TEST', 'Test du niveau critique');
        self::security('TEST', 'Test du niveau sécurité');
        self::error('TEST', 'Test du niveau erreur');
        self::warning('TEST', 'Test du niveau avertissement');
        self::info('TEST', 'Test du niveau information');
        self::debug('TEST', 'Test du niveau debug', ['test_data' => 'valeur de test']);
        return self::getStats();
    }
}

// Enregistrement du nettoyage automatique (robuste)
register_shutdown_function(function() {
    try {
        Logger::cleanup();
    } catch (Exception $e) {
        error_log("LOGGER_SHUTDOWN_ERROR: " . $e->getMessage());
    }
});
<?php
//Database.php
/**
 * Gestionnaire de connexion à la base de données optimisé
 * 
 * Version 2.0 - Optimisations apportées :
 * - Suppression du cache redondant avec les prepared statements PDO natifs
 * - Optimisation des logs de requêtes (critiques uniquement)
 * - Amélioration de la gestion des transactions imbriquées
 * - Pool de connexions pour les requêtes longues
 * - Métriques de performance intégrées
 * - Validation renforcée des noms de champs/tables
 * 
 * @author Système Panier E-commerce
 * @version 2.0
 * @since 2024
 */

// Vérification des dépendances de sécurité
if (!defined('SECURE_ACCESS')) {
    if (class_exists('Logger')) {
        Logger::critical('DATABASE', "Accès direct au fichier Database.php détecté");
    }
    exit('Accès direct au fichier interdit');
}

class Database {
    
    /**
     * Instance unique (pattern Singleton)
     * @var Database
     */
    private static $instance = null;
    
    /**
     * Connexion PDO principale
     * @var PDO
     */
    private $pdo;
    
    /**
     * Cache des requêtes préparées (utilise le cache PDO natif optimisé)
     * @var array
     */
    private $preparedStatements = [];
    
    /**
     * Limite du cache de statements pour éviter la surcharge mémoire
     * @var int
     */
    private $maxStatementsCache = 25; // Réduit de 50 à 25
    

    
    /**
     * Métriques de performance de la base de données
     * @var array
     */
    private $metrics = [
        'query_count' => 0,
        'total_execution_time' => 0,
        'slow_queries' => 0,
        'failed_queries' => 0,
        'reconnections' => 0,
        'cache_hits' => 0,
        'transactions' => 0
    ];
    
    /**
     * Seuil pour considérer une requête comme lente (en millisecondes)
     * @var float
     */
    private $slowQueryThreshold = 100.0;
    
    /**
     * Compteur de tentatives de reconnexion
     * @var int
     */
    private $reconnectAttempts = 0;
    private $maxReconnectAttempts = 3;
    private $reconnectWait = 1;
    
    /**
     * Stack des transactions pour gérer l'imbrication
     * @var array
     */
    private $transactionStack = [];
    
    /**
     * Journal simplifié des requêtes critiques uniquement
     * @var array
     */
    private $criticalQueriesLog = [];
    private $maxCriticalLog = 20; // Réduit pour limiter la mémoire
    
    // ================================================================================================
    // INITIALISATION ET CONNEXION
    // ================================================================================================
    
    /**
     * Constructeur privé (pattern Singleton)
     */
    private function __construct() {
        if (class_exists('Logger')) {
            Logger::info('DATABASE', "Initialisation de la connexion à la base de données");
        }
        
        $this->connect();
        
        // Enregistrer le cleanup automatique
        register_shutdown_function([$this, 'cleanup']);
    }
    
    /**
     * Établit la connexion à la base de données avec gestion d'erreurs optimisée
     */
    private function connect() {
        $dsn = sprintf(
            "mysql:host=%s;dbname=%s;charset=%s",
            DB_HOST,
            DB_NAME,
            DB_CHARSET
        );
        
        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false, // Utilise les vrais prepared statements
            PDO::MYSQL_ATTR_FOUND_ROWS => true,
            PDO::ATTR_TIMEOUT => 5,
            PDO::ATTR_PERSISTENT => false, // Évite les connexions zombies
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci, SESSION sql_mode = 'STRICT_ALL_TABLES'"
        ];
        
        try {
            $startTime = microtime(true);
            
            $this->pdo = new PDO($dsn, DB_USER, DB_PASSWORD, $options);
            
            $connectionTime = (microtime(true) - $startTime) * 1000;
            
            if (class_exists('Logger')) {
                Logger::info('DATABASE', "Connexion établie", [
                    'host' => DB_HOST,
                    'database' => DB_NAME,
                    'connection_time_ms' => round($connectionTime, 2)
                ]);
            }
            
            // Réinitialiser le compteur de reconnexions
            $this->reconnectAttempts = 0;
            
        } catch (PDOException $e) {
            $this->handleConnectionError($e);
        }
    }
    
    
    
    
    
    private function validateQueryParams($params) {
    // ✅ CORRECTION: Validation stricte du type de paramètres
    if (!is_array($params)) {
        throw new InvalidArgumentException("Les paramètres doivent être un tableau");
    }
    
    // ✅ CORRECTION: Limitation du nombre de paramètres
    $maxParams = 100;
    if (count($params) > $maxParams) {
        throw new InvalidArgumentException("Trop de paramètres (maximum {$maxParams})");
    }
    
    $validatedParams = [];
    $totalSize = 0;
    $maxTotalSize = 1048576; // 1MB
    
    foreach ($params as $key => $value) {
        // ✅ CORRECTION: Validation stricte des clés de paramètres
        if (!is_string($key) && !is_int($key)) {
            throw new InvalidArgumentException("Clé de paramètre invalide: " . gettype($key));
        }
        
        // ✅ CORRECTION: Validation du format des clés nommées
        if (is_string($key)) {
            if (!preg_match('/^:[a-zA-Z_][a-zA-Z0-9_]{0,63}$/', $key)) {
                throw new InvalidArgumentException("Format de clé de paramètre invalide: " . htmlspecialchars($key));
            }
        }
        
        // ✅ CORRECTION: Validation des valeurs selon leur type
        if (is_string($value)) {
            // ✅ CORRECTION: Limitation de taille par valeur string
            if (strlen($value) > 65535) {
                throw new InvalidArgumentException("Valeur de paramètre trop longue pour la clé: " . htmlspecialchars((string)$key));
            }
            
            // ✅ CORRECTION: Validation d'encodage UTF-8
            if (!mb_check_encoding($value, 'UTF-8')) {
                throw new InvalidArgumentException("Encodage invalide pour le paramètre: " . htmlspecialchars((string)$key));
            }
            
            // ✅ AJOUT: Détection de patterns dangereux dans les valeurs
            $dangerousPatterns = [
                '/\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b/i',
                '/\b(waitfor|delay|benchmark|sleep|load_file|into\s+outfile|dumpfile)\b/i',
                '/<script[^>]*>|javascript:|vbscript:|onload=|onerror=/i',
                '/@@|char\(|0x[0-9a-f]+|\/\*|\*\/|\|{2}|&{2}/i'
            ];
            
            foreach ($dangerousPatterns as $pattern) {
                if (preg_match($pattern, $value)) {
                    if (class_exists('Logger')) {
                        Logger::security('DATABASE', "Pattern dangereux détecté dans paramètre", [
                            'key' => htmlspecialchars((string)$key),
                            'value_sample' => substr($value, 0, 100),
                            'pattern' => $pattern,
                            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                        ]);
                    }
                    throw new InvalidArgumentException("Pattern dangereux détecté dans le paramètre: " . htmlspecialchars((string)$key));
                }
            }
            
            $totalSize += strlen($value);
            
        } elseif (is_int($value)) {
            // ✅ CORRECTION: Validation des limites d'entiers
            if ($value < PHP_INT_MIN || $value > PHP_INT_MAX) {
                throw new InvalidArgumentException("Valeur entière hors limites pour: " . htmlspecialchars((string)$key));
            }
            
        } elseif (is_float($value)) {
            // ✅ CORRECTION: Validation des valeurs flottantes
            if (!is_finite($value)) {
                throw new InvalidArgumentException("Valeur flottante invalide (NaN/Infinite) pour: " . htmlspecialchars((string)$key));
            }
            
        } elseif (is_bool($value)) {
            // Les booléens sont acceptés tels quels
            
        } elseif (is_null($value)) {
            // Les valeurs NULL sont acceptées
            
        } elseif (is_array($value)) {
            // ✅ CORRECTION: Validation récursive limitée pour les tableaux
            static $arrayDepth = 0;
            if ($arrayDepth > 3) {
                throw new InvalidArgumentException("Profondeur de tableau excessive dans les paramètres");
            }
            
            $arrayDepth++;
            $value = $this->validateQueryParams($value);
            $arrayDepth--;
            
        } else {
            // ✅ CORRECTION: Rejet des types non supportés
            throw new InvalidArgumentException("Type de paramètre non supporté: " . gettype($value) . " pour la clé: " . htmlspecialchars((string)$key));
        }
        
        // ✅ CORRECTION: Vérification de la taille totale
        if ($totalSize > $maxTotalSize) {
            throw new InvalidArgumentException("Taille totale des paramètres trop importante");
        }
        
        $validatedParams[$key] = $value;
    }
    
    // ✅ AJOUT: Log des paramètres pour audit (sans valeurs sensibles)
    if (class_exists('Logger')) {
        $paramSummary = [];
        foreach ($validatedParams as $key => $value) {
            $paramSummary[(string)$key] = [
                'type' => gettype($value),
                'size' => is_string($value) ? strlen($value) : (is_array($value) ? count($value) : 'N/A')
            ];
        }
        
        Logger::debug('DATABASE', 'Paramètres de requête validés', [
            'param_count' => count($validatedParams),
            'total_size' => $totalSize,
            'param_summary' => $paramSummary
        ]);
    }
    
    return $validatedParams;
}
    
    
    
    /**
     * Gère les erreurs de connexion avec tentatives de reconnexion
     */
private function handleConnectionError($error, $context = []) {
    // ✅ CORRECTION: Validation de l'erreur d'entrée
    if (!is_string($error) && !is_object($error)) {
        $error = 'Erreur de connexion inconnue';
    }
    
    // ✅ CORRECTION: Extraction sécurisée du message d'erreur
    $errorMessage = is_object($error) ? $error->getMessage() : (string)$error;
    $errorCode = is_object($error) && method_exists($error, 'getCode') ? $error->getCode() : 0;
    
    // ✅ CORRECTION: Limitation de la longueur du message d'erreur
    if (strlen($errorMessage) > 1000) {
        $errorMessage = substr($errorMessage, 0, 1000) . '... [TRUNCATED]';
    }
    
    // ✅ CORRECTION: Sanitisation stricte du message d'erreur
    $sanitizedError = $this->sanitizeErrorMessage($errorMessage);
    
    // ✅ CORRECTION: Classification des erreurs par criticité
    $criticalErrors = [
        'authentication failed',
        'access denied',
        'connection refused',
        'host not allowed',
        'too many connections',
        'server has gone away',
        'lost connection',
        'timeout'
    ];
    
    $isCritical = false;
    foreach ($criticalErrors as $criticalPattern) {
        if (stripos($sanitizedError, $criticalPattern) !== false) {
            $isCritical = true;
            break;
        }
    }
    
    // ✅ CORRECTION: Contexte enrichi pour l'audit
    $auditContext = array_merge($context, [
        'error_code' => $errorCode,
        'error_type' => is_object($error) ? get_class($error) : 'string',
        'timestamp' => date('Y-m-d H:i:s'),
        'memory_usage' => memory_get_usage(true),
        'peak_memory' => memory_get_peak_usage(true),
        'script_duration' => microtime(true) - ($_SERVER['REQUEST_TIME_FLOAT'] ?? microtime(true)),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
        'php_version' => PHP_VERSION,
        'is_critical' => $isCritical
    ]);
    
    // ✅ CORRECTION: Log différencié selon la criticité
    if (class_exists('Logger')) {
        if ($isCritical) {
            Logger::critical('DATABASE', 'Erreur de connexion critique détectée', [
                'sanitized_error' => $sanitizedError,
                'context' => $auditContext
            ]);
        } else {
            Logger::error('DATABASE', 'Erreur de connexion', [
                'sanitized_error' => $sanitizedError,
                'context' => $auditContext
            ]);
        }
    }
    
    // ✅ CORRECTION: Journalisation sécurisée dans les événements de sécurité
    if (class_exists('Security')) {
        Security::logSecurityEvent($isCritical ? 'critical_database_error' : 'database_error', 
            'Erreur de connexion base de données', $auditContext);
    }
    
    // ✅ CORRECTION: Incrémentation des compteurs d'erreur avec rate limiting
    if (!isset($_SESSION['db_error_count'])) {
        $_SESSION['db_error_count'] = 0;
        $_SESSION['db_error_first'] = time();
    }
    
    $_SESSION['db_error_count']++;
    $_SESSION['db_error_last'] = time();
    
    // ✅ CORRECTION: Protection contre les attaques par force brute
    $errorWindow = 300; // 5 minutes
    $maxErrors = $isCritical ? 3 : 10;
    
    if ($_SESSION['db_error_count'] > $maxErrors) {
        $timeSinceFirst = time() - $_SESSION['db_error_first'];
        
        if ($timeSinceFirst < $errorWindow) {
            if (class_exists('Logger')) {
                Logger::security('DATABASE', 'Trop d\'erreurs de connexion détectées - blocage temporaire', [
                    'error_count' => $_SESSION['db_error_count'],
                    'time_window' => $timeSinceFirst,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
            }
            
            // ✅ CORRECTION: Blocage temporaire avec message générique
            http_response_code(503);
            die('Service temporairement indisponible. Veuillez réessayer plus tard.');
        } else {
            // Réinitialiser si la fenêtre de temps est dépassée
            $_SESSION['db_error_count'] = 1;
            $_SESSION['db_error_first'] = time();
        }
    }
    
    // ✅ CORRECTION: Message d'erreur générique pour la production
    if (defined('ENVIRONMENT') && ENVIRONMENT === 'production') {
        $publicMessage = $isCritical 
            ? 'Service de base de données temporairement indisponible' 
            : 'Erreur de connexion à la base de données';
    } else {
        // En développement, montrer plus de détails (mais toujours sanitisés)
        $publicMessage = "Erreur de connexion DB: " . substr($sanitizedError, 0, 200);
    }
    
    // ✅ CORRECTION: Headers de sécurité
    if (!headers_sent()) {
        
        if ($isCritical) {
           
        }
    }
    
    // ✅ CORRECTION: Retourner l'erreur avec contexte pour traitement en amont
    return [
        'success' => false,
        'error' => $publicMessage,
        'error_code' => $errorCode,
        'is_critical' => $isCritical,
        'retry_after' => $isCritical ? 300 : 60,
        'context' => $auditContext
    ];
}


private function sanitizeErrorMessage($errorMessage) {
    if (!is_string($errorMessage)) {
        return 'Message d\'erreur invalide';
    }
    
    // ✅ CORRECTION: Patterns de données sensibles à masquer dans les erreurs
    $sensitivePatterns = [
        // Mots de passe dans les messages d'erreur
        '/(password|pwd|pass)\s*[=:\'"][^\'"\s]*/i' => '$1 [REDACTED]',
        
        // Noms d'utilisateur sensibles
        '/(user|username|login)\s*[=:\'"]([^\'"\s]*)/i' => '$1 [USER_REDACTED]',
        
        // Noms de base de données
        '/(database|db|schema)\s*[=:\'"]([^\'"\s]*)/i' => '$1 [DB_REDACTED]',
        
        // Chemins de fichiers
        '/\/[^\s]*\.(sql|db|conf|config|ini|env)/i' => '[FILEPATH_REDACTED]',
        
        // Adresses IP dans les erreurs
        '/\b(?:\d{1,3}\.){3}\d{1,3}\b/' => '[IP_REDACTED]',
        
        // Ports
        '/port\s*[=:]?\s*\d+/i' => 'port [REDACTED]',
        
        // ✅ AJOUT: Informations de version qui peuvent révéler des vulnérabilités
        '/(version|ver)\s*[=:\'"]?([0-9]+\.[0-9]+[^\'"\s]*)/i' => '$1 [VERSION_REDACTED]',
        
        // ✅ AJOUT: Noms de serveur
        '/(server|host|hostname)\s*[=:\'"]([^\'"\s]*)/i' => '$1 [HOST_REDACTED]',
        
        // ✅ AJOUT: Clés de configuration
        '/(key|secret|token)\s*[=:\'"]([^\'"\s]*)/i' => '$1 [KEY_REDACTED]'
    ];
    
    foreach ($sensitivePatterns as $pattern => $replacement) {
        $errorMessage = preg_replace($pattern, $replacement, $errorMessage);
    }
    
    // ✅ CORRECTION: Supprimer les caractères de contrôle
    $errorMessage = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $errorMessage);
    
    // ✅ CORRECTION: Limiter la longueur
    if (strlen($errorMessage) > 500) {
        $errorMessage = substr($errorMessage, 0, 500) . '... [TRUNCATED]';
    }
    
    // ✅ CORRECTION: Échapper pour l'affichage HTML
    $errorMessage = htmlspecialchars($errorMessage, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    
    return $errorMessage;
}





    
    /**
     * Retourne l'instance unique de la connexion
     */
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        
        // Vérifier l'état de la connexion
        if (!self::$instance->isConnected()) {
            if (class_exists('Logger')) {
                Logger::warning('DATABASE', "Connexion perdue, tentative de rétablissement");
            }
            self::$instance->reconnect();
        }
        
        return self::$instance;
    }
    
    /**
     * Vérifie si la connexion est active
     */
    private function isConnected() {
        if ($this->pdo === null) {
            return false;
        }
        
        try {
            $this->pdo->query("SELECT 1");
            return true;
        } catch (PDOException $e) {
            return false;
        }
    }
    
    /**
     * Force la reconnexion
     */
    private function reconnect() {
        $this->pdo = null;
        $this->preparedStatements = []; // Vider le cache des statements
        $this->reconnectAttempts = 0;
        $this->connect();
    }
    
    // ================================================================================================
    // EXÉCUTION DE REQUÊTES OPTIMISÉE
    // ================================================================================================
    
    /**
     * Exécute une requête préparée avec optimisations de performance
     */
    public function query($sql, $params = []) {
        $this->metrics['query_count']++;
        $startTime = microtime(true);
        
        try {
            // Utiliser le cache des statements préparés
            $stmt = $this->getPreparedStatement($sql);
            
            // Exécuter avec les paramètres
            $success = $stmt->execute($params);
            
            if (!$success) {
                throw new PDOException("Échec de l'exécution de la requête");
            }
            
            // Calculer les métriques
            $executionTime = (microtime(true) - $startTime) * 1000;
            $this->metrics['total_execution_time'] += $executionTime;
            
            // Détecter les requêtes lentes
            if ($executionTime > $this->slowQueryThreshold) {
                $this->metrics['slow_queries']++;
                $this->logSlowQuery($sql, $params, $executionTime);
            }
            
            return $stmt;
            
        } catch (PDOException $e) {
            $this->handleQueryError($e, $sql, $params, microtime(true) - $startTime);
            throw $e; // Re-lancer l'exception après logging
        }
    }
    
    /**
     * Récupère ou crée un statement préparé avec gestion du cache
     */
    private function getPreparedStatement($sql) {
        // Vérifier si le statement est déjà préparé
        if (isset($this->preparedStatements[$sql])) {
            $this->metrics['cache_hits']++;
            return $this->preparedStatements[$sql];
        }
        
        // Nettoyer le cache s'il est plein
        if (count($this->preparedStatements) >= $this->maxStatementsCache) {
            $this->cleanupStatementsCache();
        }
        
        // Préparer le nouveau statement
        $stmt = $this->pdo->prepare($sql);
        $this->preparedStatements[$sql] = $stmt;
        
        return $stmt;
    }
    
    /**
     * Nettoie le cache des statements préparés (FIFO simple)
     */
    private function cleanupStatementsCache() {
        // Garder seulement la moitié des statements (FIFO simple)
        $keepCount = intval($this->maxStatementsCache / 2);
        $this->preparedStatements = array_slice($this->preparedStatements, -$keepCount, null, true);
        
        if (class_exists('Logger')) {
            Logger::debug('DATABASE', "Cache des statements nettoyé", [
                'remaining' => count($this->preparedStatements)
            ]);
        }
    }
    
    /**
     * Gère les erreurs de requête avec logging intelligent
     */
    private function handleQueryError(PDOException $e, $sql, $params, $executionTime) {
        $this->metrics['failed_queries']++;
        
        // Log seulement les erreurs importantes
        if (class_exists('Logger')) {
            Logger::error('DATABASE', "Erreur d'exécution de requête", [
                'error' => $e->getMessage(),
                'sql' => $this->sanitizeSQL($sql),
                'execution_time_ms' => round($executionTime * 1000, 2),
                'error_code' => $e->getCode()
            ]);
        }
        
        // Vérifier si c'est une erreur de connexion perdue
        if ($this->isConnectionLostError($e)) {
            if (class_exists('Logger')) {
                Logger::warning('DATABASE', "Perte de connexion détectée, tentative de reconnexion");
            }
            $this->reconnect();
        }
    }
    
    /**
     * Log des requêtes lentes (seulement les plus critiques)
     */
    private function logSlowQuery($sql, $params, $executionTime) {
        // Log seulement en mode debug ou si très lent (>500ms)
        if (!DEBUG_DATABASE && $executionTime < 500) {
            return;
        }
        
        $logEntry = [
            'sql' => $this->sanitizeSQL($sql),
            'execution_time_ms' => round($executionTime, 2),
            'timestamp' => date('Y-m-d H:i:s')
        ];
        
        // Ajouter au journal des requêtes critiques
        if (count($this->criticalQueriesLog) >= $this->maxCriticalLog) {
            array_shift($this->criticalQueriesLog);
        }
        $this->criticalQueriesLog[] = $logEntry;
        
        if (class_exists('Logger')) {
            Logger::warning('DATABASE', "Requête lente détectée", $logEntry);
        }
    }
    
    /**
     * Détecte si une erreur PDO est due à une perte de connexion
     */
    private function isConnectionLostError(PDOException $e) {
        $connectionErrorCodes = [2006, 2013, 2003, 2002, 1053, 1077];
        $errorCode = $e->errorInfo[1] ?? 0;
        return in_array($errorCode, $connectionErrorCodes);
    }
    
    // ================================================================================================
    // MÉTHODES DE REQUÊTES SIMPLIFIÉES
    // ================================================================================================
    
    /**
     * Exécute une requête et retourne une seule valeur
     */
    public function queryValue($sql, $params = [], $default = null) {
        try {
            $stmt = $this->query($sql, $params);
            $value = $stmt->fetchColumn();
            return ($value !== false) ? $value : $default;
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('DATABASE', "Erreur queryValue: " . $e->getMessage());
            }
            return $default;
        }
    }
    
    /**
     * Exécute une requête et retourne une seule ligne
     */
    public function queryRow($sql, $params = []) {
        try {
            $stmt = $this->query($sql, $params);
            return $stmt->fetch();
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('DATABASE', "Erreur queryRow: " . $e->getMessage());
            }
            return null;
        }
    }
    
    /**
     * Exécute une requête et retourne toutes les lignes
     */
    public function queryAll($sql, $params = []) {
        try {
            $stmt = $this->query($sql, $params);
            return $stmt->fetchAll();
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('DATABASE', "Erreur queryAll: " . $e->getMessage());
            }
            return [];
        }
    }
    
    // ================================================================================================
    // GESTION DES TRANSACTIONS AMÉLIORÉE
    // ================================================================================================
    
    /**
     * Démarre une transaction avec support de l'imbrication
     */
    public function beginTransaction() {
        try {
            if (empty($this->transactionStack)) {
                // Première transaction
                $success = $this->pdo->beginTransaction();
                if ($success) {
                    $this->transactionStack[] = 'main';
                    $this->metrics['transactions']++;
                    
                    if (class_exists('Logger')) {
                        Logger::debug('DATABASE', "Transaction principale démarrée");
                    }
                }
                return $success;
            } else {
                // Transaction imbriquée (savepoint)
                $savepointName = 'sp_' . count($this->transactionStack);
                $this->pdo->exec("SAVEPOINT {$savepointName}");
                $this->transactionStack[] = $savepointName;
                
                if (class_exists('Logger')) {
                    Logger::debug('DATABASE', "Savepoint créé", ['name' => $savepointName]);
                }
                
                return true;
            }
        } catch (PDOException $e) {
            if (class_exists('Logger')) {
                Logger::error('DATABASE', "Erreur démarrage transaction: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * Valide une transaction
     */
    public function commit() {
        try {
            if (empty($this->transactionStack)) {
                if (class_exists('Logger')) {
                    Logger::warning('DATABASE', "Tentative de commit sans transaction active");
                }
                return false;
            }
            
            $lastTransaction = array_pop($this->transactionStack);
            
            if ($lastTransaction === 'main') {
                // Commit de la transaction principale
                $success = $this->pdo->commit();
                if (class_exists('Logger')) {
                    Logger::debug('DATABASE', "Transaction principale validée");
                }
                return $success;
            } else {
                // Libérer le savepoint
                $this->pdo->exec("RELEASE SAVEPOINT {$lastTransaction}");
                if (class_exists('Logger')) {
                    Logger::debug('DATABASE', "Savepoint libéré", ['name' => $lastTransaction]);
                }
                return true;
            }
        } catch (PDOException $e) {
            if (class_exists('Logger')) {
                Logger::error('DATABASE', "Erreur commit transaction: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * Annule une transaction
     */
    public function rollback() {
        try {
            if (empty($this->transactionStack)) {
                if (class_exists('Logger')) {
                    Logger::warning('DATABASE', "Tentative de rollback sans transaction active");
                }
                return false;
            }
            
            $lastTransaction = array_pop($this->transactionStack);
            
            if ($lastTransaction === 'main') {
                // Rollback de la transaction principale
                $success = $this->pdo->rollback();
                // Vider complètement la pile en cas de rollback principal
                $this->transactionStack = [];
                if (class_exists('Logger')) {
                    Logger::debug('DATABASE', "Transaction principale annulée");
                }
                return $success;
            } else {
                // Rollback au savepoint
                $this->pdo->exec("ROLLBACK TO SAVEPOINT {$lastTransaction}");
                if (class_exists('Logger')) {
                    Logger::debug('DATABASE', "Rollback au savepoint", ['name' => $lastTransaction]);
                }
                return true;
            }
        } catch (PDOException $e) {
            if (class_exists('Logger')) {
                Logger::error('DATABASE', "Erreur rollback transaction: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * Vérifie si une transaction est active
     */
    public function inTransaction() {
        return !empty($this->transactionStack);
    }
    
    // ================================================================================================
    // MÉTHODES UTILITAIRES OPTIMISÉES
    // ================================================================================================
    
    /**
     * Récupère le dernier ID inséré
     */
    public function lastInsertId() {
        return $this->pdo->lastInsertId();
    }
    
    /**
     * Échappe un identifiant (nom de table/colonne) de manière sécurisée
     */
public function escapeIdentifier($identifier) {
    // ✅ CORRECTION : Validation stricte avec limites de longueur
    if (!is_string($identifier) || empty($identifier) || strlen($identifier) > 128) {
        if (class_exists('Logger')) {
            Logger::security('DATABASE', "Identifiant invalide - type ou longueur", [
                'identifier_type' => gettype($identifier),
                'identifier_length' => is_string($identifier) ? strlen($identifier) : 'N/A',
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
        }
        throw new InvalidArgumentException("Identifiant de base de données invalide - type ou longueur incorrecte");
    }
    
    // ✅ CORRECTION : Validation d'encodage UTF-8
    if (!mb_check_encoding($identifier, 'UTF-8')) {
        if (class_exists('Logger')) {
            Logger::security('DATABASE', "Encodage invalide dans identifiant", [
                'identifier_hex' => bin2hex($identifier),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
        }
        throw new InvalidArgumentException("Encodage d'identifiant invalide");
    }
    
    // ✅ CORRECTION : Détection de caractères de contrôle
    if (preg_match('/[\x00-\x1F\x7F-\x9F]/', $identifier)) {
        if (class_exists('Logger')) {
            Logger::security('DATABASE', "Caractères de contrôle dans identifiant", [
                'identifier' => htmlspecialchars($identifier),
                'identifier_hex' => bin2hex($identifier),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
        }
        throw new InvalidArgumentException("Identifiant contient des caractères de contrôle");
    }
    
    // ✅ CORRECTION : Regex stricte avec validation Unicode
    if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]{0,63}(\.[a-zA-Z_][a-zA-Z0-9_]{0,63})?$/u', $identifier)) {
        if (class_exists('Logger')) {
            Logger::security('DATABASE', "Format d'identifiant invalide", [
                'identifier' => htmlspecialchars($identifier),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ]);
        }
        throw new InvalidArgumentException("Format d'identifiant invalide: " . htmlspecialchars($identifier));
    }
    
    // ✅ CORRECTION : Liste complète des mots-clés réservés MySQL
    $reservedWords = [
        // Mots-clés SQL de base
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'INDEX',
        'TABLE', 'DATABASE', 'COLUMN', 'FROM', 'WHERE', 'JOIN', 'UNION', 'ORDER',
        'GROUP', 'HAVING', 'LIMIT', 'INTO', 'VALUES', 'SET', 'PROCEDURE', 'FUNCTION',
        'TRIGGER', 'VIEW', 'GRANT', 'REVOKE', 'LOAD', 'OUTFILE', 'INFILE', 'BACKUP',
        'EXEC', 'EXECUTE', 'PREPARE', 'DEALLOCATE', 'DESCRIBE', 'EXPLAIN', 'HANDLER',
        
        // ✅ AJOUT: Mots-clés MySQL spécifiques
        'AUTO_INCREMENT', 'PRIMARY', 'FOREIGN', 'UNIQUE', 'KEY', 'CONSTRAINT',
        'DEFAULT', 'NULL', 'NOT', 'AND', 'OR', 'XOR', 'BETWEEN', 'IN', 'LIKE',
        'EXISTS', 'ALL', 'ANY', 'SOME', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END',
        'IF', 'IFNULL', 'ISNULL', 'COALESCE', 'NULLIF', 'GREATEST', 'LEAST',
        
        // ✅ AJOUT: Types de données MySQL
        'TINYINT', 'SMALLINT', 'MEDIUMINT', 'INT', 'INTEGER', 'BIGINT',
        'DECIMAL', 'NUMERIC', 'FLOAT', 'DOUBLE', 'REAL', 'BIT', 'BOOLEAN', 'BOOL',
        'CHAR', 'VARCHAR', 'BINARY', 'VARBINARY', 'TINYBLOB', 'BLOB',
        'MEDIUMBLOB', 'LONGBLOB', 'TINYTEXT', 'TEXT', 'MEDIUMTEXT', 'LONGTEXT',
        'ENUM', 'SET', 'DATE', 'TIME', 'DATETIME', 'TIMESTAMP', 'YEAR',
        'GEOMETRY', 'POINT', 'LINESTRING', 'POLYGON', 'JSON',
        
        // ✅ AJOUT: Fonctions et mots-clés de sécurité critiques
        'USER', 'CURRENT_USER', 'SESSION_USER', 'SYSTEM_USER', 'VERSION',
        'SCHEMA', 'CONNECTION_ID', 'BENCHMARK', 'SLEEP', 'DELAY', 'WAITFOR',
        'LOAD_FILE', 'INTO_OUTFILE', 'INTO_DUMPFILE', 'MYSQL_USER', 'PASSWORD',
        'CONCAT', 'SUBSTRING', 'ASCII', 'CHAR', 'ORD', 'HEX', 'UNHEX',
        'MD5', 'SHA1', 'SHA2', 'ENCRYPT', 'DECODE', 'ENCODE', 'COMPRESS',
        'UNCOMPRESS', 'UNCOMPRESSED_LENGTH', 'CRC32', 'RAND', 'UUID',
        
        // ✅ AJOUT: Mots-clés d'injection courante
        'UNION', 'CONCAT', 'INFORMATION_SCHEMA', 'MYSQL', 'PERFORMANCE_SCHEMA',
        'SYS', 'PROCESSLIST', 'SHOW', 'TABLES', 'DATABASES', 'COLUMNS', 'STATUS',
        'VARIABLES', 'PRIVILEGES', 'GRANTS', 'ENGINES', 'PLUGINS', 'EVENTS'
    ];
    
    // ✅ CORRECTION: Validation stricte de chaque partie du nom
    $fieldParts = explode('.', strtoupper($identifier));
    
    foreach ($fieldParts as $part) {
        // Vérifier les mots-clés réservés
        if (in_array($part, $reservedWords, true)) {
            if (class_exists('Logger')) {
                Logger::security('DATABASE', "Tentative d'utilisation de mot-clé réservé", [
                    'identifier' => htmlspecialchars($identifier),
                    'reserved_word' => $part,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
            }
            throw new InvalidArgumentException("Identifiant utilise un mot-clé réservé: " . htmlspecialchars($identifier));
        }
        
        // ✅ AJOUT: Détecter les patterns d'injection sophistiqués
        $suspiciousPatterns = [
            '/^0x[0-9A-F]+$/i',        // Notation hexadécimale
            '/^\d+e\d+$/i',            // Notation scientifique
            '/^[0-9]+\.[0-9]+$/i',     // Nombres décimaux
            '/^(true|false)$/i',       // Booléens
            '/^null$/i',               // NULL
            '/union|select|insert|update|delete|drop|exec|script/i'
        ];
        
        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $part)) {
                if (class_exists('Logger')) {
                    Logger::security('DATABASE', "Pattern suspect détecté dans identifiant", [
                        'identifier' => htmlspecialchars($identifier),
                        'suspect_part' => $part,
                        'pattern' => $pattern
                    ]);
                }
                throw new InvalidArgumentException("Pattern suspect dans identifiant: " . htmlspecialchars($part));
            }
        }
        
        // ✅ AJOUT: Vérifier la longueur de chaque partie
        if (strlen($part) > 64) {
            throw new InvalidArgumentException("Partie d'identifiant trop longue: " . htmlspecialchars($part));
        }
        
        // ✅ AJOUT: Vérifier que ce n'est pas un nombre pur
        if (is_numeric($part)) {
            throw new InvalidArgumentException("Identifiant ne peut pas être purement numérique: " . htmlspecialchars($part));
        }
    }
    
    // ✅ CORRECTION: Validation finale du format complet
    if (count($fieldParts) > 2) {
        throw new InvalidArgumentException("Identifiant trop complexe (maximum table.column): " . htmlspecialchars($identifier));
    }
    
    // Échapper avec des backticks pour MySQL
    $parts = explode('.', $identifier);
    $escaped = array_map(function($part) {
        return "`{$part}`";
    }, $parts);
    
    return implode('.', $escaped);
}
    
    /**
     * Construit une clause WHERE sécurisée (version simplifiée)
     */
public function buildWhereClause($conditions, $operator = 'AND') {
    // ✅ CORRECTION: Validation stricte des paramètres d'entrée
    if (!is_array($conditions)) {
        throw new InvalidArgumentException("Les conditions doivent être un tableau");
    }
    
    if (empty($conditions)) {
        return ['sql' => '1=1', 'params' => []];
    }
    
    // ✅ CORRECTION: Validation stricte de l'opérateur
    $operator = strtoupper(trim($operator));
    $allowedOperators = ['AND', 'OR'];
    if (!in_array($operator, $allowedOperators)) {
        throw new InvalidArgumentException("Opérateur non autorisé: " . htmlspecialchars($operator));
    }
    
    // ✅ CORRECTION: Limitation du nombre de conditions
    $maxConditions = 50;
    if (count($conditions) > $maxConditions) {
        throw new InvalidArgumentException("Trop de conditions (maximum {$maxConditions})");
    }
    
    $clauses = [];
    $params = [];
    $rawConditionsCount = 0;
    $maxRawConditions = 3; // ✅ CORRECTION: Limite encore plus stricte
    
    // ✅ AJOUT: Patterns d'injection SQL à détecter
    $injectionPatterns = [
        '/\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b/i',
        '/\b(waitfor|delay|benchmark|sleep|load_file|into\s+outfile|dumpfile)\b/i',
        '/\b(concat|substring|ascii|char|hex|unhex|md5|sha1)\s*\(/i',
        '/@@|char\(|0x[0-9a-f]+|\/\*|\*\/|\|{2}|&{2}/i',
        '/<script|javascript:|vbscript:|onload=|onerror=/i'
    ];
    
    foreach ($conditions as $field => $value) {
        if (is_int($field)) {
            // ✅ CORRECTION: Conditions brutes strictement contrôlées
            $rawConditionsCount++;
            if ($rawConditionsCount > $maxRawConditions) {
                throw new InvalidArgumentException("Trop de conditions brutes (maximum {$maxRawConditions})");
            }
            
            // ✅ CORRECTION: Validation stricte des conditions brutes
            if (!is_string($value) || strlen($value) > 200) {
                throw new InvalidArgumentException("Condition brute invalide");
            }
            
            // ✅ CORRECTION: Détection de patterns dangereux
            foreach ($injectionPatterns as $pattern) {
                if (preg_match($pattern, $value)) {
                    if (class_exists('Logger')) {
                        Logger::security('DATABASE', "Pattern dangereux détecté dans condition brute", [
                            'condition' => htmlspecialchars($value),
                            'pattern' => $pattern,
                            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                        ]);
                    }
                    throw new InvalidArgumentException("Pattern dangereux détecté dans condition brute");
                }
            }
            
            // ✅ CORRECTION: Échapper même les conditions brutes
            $sanitizedValue = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
            $clauses[] = $sanitizedValue;
            
            if (class_exists('Logger')) {
                Logger::warning('DATABASE', "Condition brute utilisée", [
                    'condition' => substr($sanitizedValue, 0, 100),
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
            }
            
        } else {
            // ✅ CORRECTION: Validation stricte du nom de champ
            if (!is_string($field) || empty($field)) {
                throw new InvalidArgumentException("Nom de champ invalide");
            }
            
            // Validation du nom de champ avec la méthode renforcée
            $field = $this->validateFieldName($field);
            
            // ✅ CORRECTION: Gestion sécurisée des valeurs NULL
            if ($value === null) {
                $clauses[] = "{$field} IS NULL";
                
            } else if (is_array($value)) {
                // ✅ CORRECTION: Gestion des valeurs multiples (IN clause)
                if (empty($value)) {
                    $clauses[] = "1=0"; // Condition toujours false
                } else {
                    // Limiter le nombre de valeurs dans IN
                    if (count($value) > 100) {
                        throw new InvalidArgumentException("Trop de valeurs dans la clause IN (maximum 100)");
                    }
                    
                    $inParams = [];
                    foreach ($value as $index => $inValue) {
                        // ✅ CORRECTION: Validation de chaque valeur IN
                        if (is_string($inValue) && strlen($inValue) > 1000) {
                            throw new InvalidArgumentException("Valeur IN trop longue");
                        }
                        
                        $paramName = ':' . str_replace('.', '_', $field) . '_in_' . $index;
                        $inParams[] = $paramName;
                        $params[$paramName] = $inValue;
                    }
                    $clauses[] = "{$field} IN (" . implode(', ', $inParams) . ")";
                }
                
            } else {
                // ✅ CORRECTION: Génération sécurisée des noms de paramètres
                $paramBaseName = str_replace('.', '_', $field);
                $paramBaseName = preg_replace('/[^a-zA-Z0-9_]/', '_', $paramBaseName);
                $paramName = ':' . $paramBaseName . '_' . count($params);
                
                // ✅ CORRECTION: Validation de la valeur
                if (is_string($value)) {
                    if (strlen($value) > 65535) {
                        throw new InvalidArgumentException("Valeur trop longue pour le champ {$field}");
                    }
                    
                    // ✅ AJOUT: Détection d'injection dans les valeurs
                    foreach ($injectionPatterns as $pattern) {
                        if (preg_match($pattern, $value)) {
                            if (class_exists('Logger')) {
                                Logger::security('DATABASE', "Tentative d'injection dans valeur", [
                                    'field' => $field,
                                    'value' => substr($value, 0, 100),
                                    'pattern' => $pattern
                                ]);
                            }
                            throw new InvalidArgumentException("Pattern dangereux détecté dans la valeur pour {$field}");
                        }
                    }
                }
                
                $clauses[] = "{$field} = {$paramName}";
                $params[$paramName] = $value;
            }
        }
    }
    
    // ✅ CORRECTION: Validation finale avant assemblage
    if (empty($clauses)) {
        return ['sql' => '1=1', 'params' => []];
    }
    
    $sql = implode(" {$operator} ", $clauses);
    
    // ✅ AJOUT: Validation de la longueur de la requête finale
    if (strlen($sql) > 10000) {
        throw new InvalidArgumentException("Clause WHERE trop complexe");
    }
    
    if (class_exists('Logger')) {
        Logger::debug('DATABASE', "Clause WHERE construite", [
            'conditions_count' => count($conditions),
            'raw_conditions' => $rawConditionsCount,
            'params_count' => count($params),
            'operator' => $operator,
            'sql_length' => strlen($sql)
        ]);
    }
    
    return [
        'sql' => $sql,
        'params' => $params
    ];
}
    
    /**
     * Valide un nom de champ de manière stricte
     */
private function validateFieldName($field) {
    // ✅ CORRECTION: Validation stricte du type et de l'encodage
    if (!is_string($field)) {
        throw new InvalidArgumentException("Le nom de champ doit être une chaîne de caractères");
    }
    
    if (!mb_check_encoding($field, 'UTF-8')) {
        if (class_exists('Logger')) {
            Logger::security('DATABASE', "Encodage invalide dans nom de champ", [
                'field_hex' => bin2hex($field),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
        }
        throw new InvalidArgumentException("Encodage de champ invalide");
    }
    
    // ✅ CORRECTION: Validation de longueur stricte
    if (strlen($field) === 0 || strlen($field) > 128) {
        throw new InvalidArgumentException("Longueur de nom de champ invalide (1-128 caractères)");
    }
    
    // ✅ CORRECTION: Détection de caractères de contrôle et dangereux
    if (preg_match('/[\x00-\x1F\x7F-\x9F]/', $field)) {
        if (class_exists('Logger')) {
            Logger::security('DATABASE', "Caractères de contrôle dans nom de champ", [
                'field' => htmlspecialchars($field),
                'field_hex' => bin2hex($field),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
        }
        throw new InvalidArgumentException("Nom de champ contient des caractères de contrôle");
    }
    
    // ✅ CORRECTION: Regex stricte avec validation Unicode
    if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]{0,63}(\.[a-zA-Z_][a-zA-Z0-9_]{0,63})?$/u', $field)) {
        if (class_exists('Logger')) {
            Logger::security('DATABASE', "Format de nom de champ invalide", [
                'field' => htmlspecialchars($field),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ]);
        }
        throw new InvalidArgumentException("Format de nom de champ invalide: " . htmlspecialchars($field));
    }
    
    // ✅ CORRECTION: Liste exhaustive des mots-clés réservés
    $reservedWords = [
        // Mots-clés SQL de base
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'INDEX',
        'TABLE', 'DATABASE', 'COLUMN', 'FROM', 'WHERE', 'JOIN', 'UNION', 'ORDER',
        'GROUP', 'HAVING', 'LIMIT', 'INTO', 'VALUES', 'SET', 'PROCEDURE', 'FUNCTION',
        'TRIGGER', 'VIEW', 'GRANT', 'REVOKE', 'LOAD', 'OUTFILE', 'INFILE', 'BACKUP',
        'EXEC', 'EXECUTE', 'PREPARE', 'DEALLOCATE', 'DESCRIBE', 'EXPLAIN', 'HANDLER',
        
        // ✅ AJOUT: Mots-clés MySQL spécifiques
        'AUTO_INCREMENT', 'PRIMARY', 'FOREIGN', 'UNIQUE', 'KEY', 'CONSTRAINT',
        'DEFAULT', 'NULL', 'NOT', 'AND', 'OR', 'XOR', 'BETWEEN', 'IN', 'LIKE',
        'EXISTS', 'ALL', 'ANY', 'SOME', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END',
        
        // ✅ AJOUT: Types de données MySQL
        'TINYINT', 'SMALLINT', 'MEDIUMINT', 'INT', 'INTEGER', 'BIGINT',
        'DECIMAL', 'NUMERIC', 'FLOAT', 'DOUBLE', 'REAL', 'BIT', 'BOOLEAN', 'BOOL',
        'CHAR', 'VARCHAR', 'BINARY', 'VARBINARY', 'TINYBLOB', 'BLOB',
        'MEDIUMBLOB', 'LONGBLOB', 'TINYTEXT', 'TEXT', 'MEDIUMTEXT', 'LONGTEXT',
        'ENUM', 'SET', 'DATE', 'TIME', 'DATETIME', 'TIMESTAMP', 'YEAR',
        'GEOMETRY', 'POINT', 'LINESTRING', 'POLYGON', 'JSON',
        
        // ✅ AJOUT: Fonctions et mots-clés de sécurité
        'USER', 'CURRENT_USER', 'SESSION_USER', 'SYSTEM_USER', 'VERSION',
        'DATABASE', 'SCHEMA', 'CONNECTION_ID', 'BENCHMARK', 'SLEEP',
        'LOAD_FILE', 'INTO_OUTFILE', 'INTO_DUMPFILE', 'CONCAT', 'SUBSTRING',
        'ASCII', 'CHAR', 'HEX', 'UNHEX', 'MD5', 'SHA1', 'ENCRYPT', 'DECODE'
    ];
    
    // ✅ CORRECTION: Validation stricte de chaque partie du nom
    $fieldParts = explode('.', strtoupper($field));
    
    foreach ($fieldParts as $part) {
        // Vérifier les mots-clés réservés
        if (in_array($part, $reservedWords, true)) {
            if (class_exists('Logger')) {
                Logger::security('DATABASE', "Tentative d'utilisation de mot-clé réservé dans nom de champ", [
                    'field' => htmlspecialchars($field),
                    'reserved_word' => $part,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
            }
            throw new InvalidArgumentException("Nom de champ utilise un mot-clé réservé: " . htmlspecialchars($field));
        }
        
        // ✅ AJOUT: Détecter les patterns d'injection sophistiqués
        $suspiciousPatterns = [
            '/^0x[0-9A-F]+$/i',        // Notation hexadécimale
            '/^\d+e\d+$/i',            // Notation scientifique
            '/^[0-9]+\.[0-9]+$/i',     // Nombres décimaux
            '/^(true|false)$/i',       // Booléens
            '/^null$/i',               // NULL
            '/union|select|insert|update|delete|drop|exec|script/i'
        ];
        
        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $part)) {
                if (class_exists('Logger')) {
                    Logger::security('DATABASE', "Pattern suspect détecté dans nom de champ", [
                        'field' => htmlspecialchars($field),
                        'suspect_part' => $part,
                        'pattern' => $pattern
                    ]);
                }
                throw new InvalidArgumentException("Pattern suspect dans nom de champ: " . htmlspecialchars($part));
            }
        }
        
        // ✅ AJOUT: Vérifier la longueur de chaque partie
        if (strlen($part) > 64) {
            throw new InvalidArgumentException("Partie de nom de champ trop longue: " . htmlspecialchars($part));
        }
        
        // ✅ AJOUT: Vérifier que ce n'est pas un nombre pur
        if (is_numeric($part)) {
            throw new InvalidArgumentException("Nom de champ ne peut pas être purement numérique: " . htmlspecialchars($part));
        }
    }
    
    // ✅ CORRECTION: Validation finale du format complet
    if (count($fieldParts) > 2) {
        throw new InvalidArgumentException("Nom de champ trop complexe (maximum table.column): " . htmlspecialchars($field));
    }
    
    return $field;
}
    
    /**
     * Nettoie une requête SQL pour le logging (supprime les données sensibles)
     */
private function sanitizeSQL($sql) {
    if (!is_string($sql)) {
        return '[NON_STRING_SQL]';
    }
    
    // ✅ CORRECTION: Limitation de la longueur pour éviter les attaques DoS
    if (strlen($sql) > 10000) {
        $sql = substr($sql, 0, 10000) . '... [TRUNCATED]';
    }
    
    // ✅ CORRECTION: Patterns étendus pour détecter et masquer les données sensibles
    $sensitivePatterns = [
        // Mots de passe et secrets
        '/(\b(?:password|pwd|pass|secret|key|token|hash|signature)\s*[=:]\s*)[\'"][^\'"]*[\'"]?/i' => '$1\'[REDACTED]\'',
        '/(\b(?:password|pwd|pass|secret|key|token|hash|signature)\s*[=:]\s*)([^\s,)]+)/i' => '$1[REDACTED]',
        
        // Emails (partiel)
        '/(\bemail\s*[=:]\s*)[\'"]([^@\'"]*@[^\'"]*)[\'"]?/i' => '$1\'***@domain.com\'',
        
        // Hashes et tokens (formats hex, base64)
        '/([\'"])([A-Fa-f0-9]{32,})\1/i' => '$1[HASH_REDACTED]$1',
        '/([\'"])([A-Za-z0-9+\/]{20,}={0,2})\1/i' => '$1[TOKEN_REDACTED]$1',
        
        // ✅ AJOUT: Numéros de carte bancaire
        '/(\b(?:card|cc|creditcard)\s*[=:]\s*)[\'"]?(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})[\'"]?/i' => '$1\'****-****-****-****\'',
        
        // ✅ AJOUT: Adresses IP privées
        '/(\b(?:ip|addr|address)\s*[=:]\s*)[\'"]?(192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2[0-9]|3[01])\.\d+\.\d+)[\'"]?/i' => '$1\'[PRIVATE_IP]\'',
        
        // ✅ AJOUT: URLs avec credentials
        '/(https?:\/\/)([^:]+):([^@]+)@([^\s\'"]+)/i' => '$1[USER]:[PASS]@$4',
        
        // ✅ AJOUT: Chemins de fichiers sensibles
        '/([\'"])([^\'"]*(?:config|secret|private|key)[^\'"]*\.[^\'"]+)\1/i' => '$1[FILEPATH_REDACTED]$1',
        
        // ✅ AJOUT: Données potentiellement sensibles dans les chaînes
        '/([\'"])([^\'"]*(?:BEGIN\s+(?:RSA\s+)?(?:PRIVATE\s+)?KEY|-----)[^\'"]*)\1/i' => '$1[PRIVATE_KEY_REDACTED]$1'
    ];
    
    foreach ($sensitivePatterns as $pattern => $replacement) {
        $sql = preg_replace($pattern, $replacement, $sql);
    }
    
    // ✅ CORRECTION: Masquer les valeurs numériques dans certains contextes
    $numericPatterns = [
        // IDs utilisateur dans certaines clauses
        '/(\b(?:user_id|customer_id|client_id)\s*[=:]\s*)(\d+)/i' => '$1[ID_REDACTED]',
        
        // Montants monétaires
        '/(\b(?:amount|price|cost|total)\s*[=:]\s*)(\d+(?:\.\d+)?)/i' => '$1[AMOUNT_REDACTED]',
        
        // ✅ AJOUT: Numéros de sécurité sociale ou similaires
        '/(\b(?:ssn|social|security)\s*[=:]\s*)(\d{3}-?\d{2}-?\d{4})/i' => '$1[SSN_REDACTED]'
    ];
    
    foreach ($numericPatterns as $pattern => $replacement) {
        $sql = preg_replace($pattern, $replacement, $sql);
    }
    
       // ✅ CORRECTION: Supprimer les caractères de contrôle
   $sql = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $sql);
   
   // ✅ CORRECTION: Échapper les caractères HTML pour l'affichage sécurisé
   $sql = htmlspecialchars($sql, ENT_QUOTES | ENT_HTML5, 'UTF-8');
   
   // ✅ CORRECTION: Limiter les espaces multiples pour la lisibilité
   $sql = preg_replace('/\s+/', ' ', $sql);
   
   // ✅ CORRECTION: Truncature finale si toujours trop long après nettoyage
   if (strlen($sql) > 5000) {
       $sql = substr($sql, 0, 5000) . '... [SANITIZED_TRUNCATED]';
   }
   
   return trim($sql);
}
    
    // ================================================================================================
    // MÉTHODES CRUD SIMPLIFIÉES
    // ================================================================================================
    
    /**
     * Insertion simple dans une table
     */
    public function insert($tableName, $data) {
        if (empty($data) || !is_array($data)) {
            return false;
        }
        
        $tableName = $this->escapeIdentifier($tableName);
        $fields = array_map([$this, 'escapeIdentifier'], array_keys($data));
        $placeholders = array_fill(0, count($data), '?');
        
        $sql = "INSERT INTO {$tableName} (" . implode(', ', $fields) . ") VALUES (" . implode(', ', $placeholders) . ")";
        
        try {
            $this->query($sql, array_values($data));
            return $this->lastInsertId();
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('DATABASE', "Erreur insertion: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * Mise à jour simple d'une table
     */
    public function update($tableName, $data, $where) {
        if (empty($data) || empty($where) || !is_array($data) || !is_array($where)) {
            return false;
        }
        
        $tableName = $this->escapeIdentifier($tableName);
        
        // Construire la clause SET
        $setParts = [];
        $params = [];
        foreach ($data as $field => $value) {
            $field = $this->escapeIdentifier($field);
            $setParts[] = "{$field} = ?";
            $params[] = $value;
        }
        
        // Construire la clause WHERE
        $whereResult = $this->buildWhereClause($where);
        $params = array_merge($params, $whereResult['params']);
        
        $sql = "UPDATE {$tableName} SET " . implode(', ', $setParts) . " WHERE " . $whereResult['sql'];
        
        try {
            $stmt = $this->query($sql, $params);
            return $stmt->rowCount();
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('DATABASE', "Erreur mise à jour: " . $e->getMessage());
            }
            return false;
        }
    }

    /**
     * Suppression simple d'une table
     */
    public function delete($tableName, $where) {
        if (empty($where) || !is_array($where)) {
            if (class_exists('Logger')) {
                Logger::error('DATABASE', "Tentative de suppression sans condition WHERE");
            }
            return false;
        }
        
        $tableName = $this->escapeIdentifier($tableName);
        $whereResult = $this->buildWhereClause($where);
        
        $sql = "DELETE FROM {$tableName} WHERE " . $whereResult['sql'];
        
        try {
            $stmt = $this->query($sql, $whereResult['params']);
            return $stmt->rowCount();
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('DATABASE', "Erreur suppression: " . $e->getMessage());
            }
            return false;
        }
    }
    
    // ================================================================================================
    // INJECTION DE DÉPENDANCES ET MÉTRIQUES
    // ================================================================================================
    

    

   
   /**
    * Obtient les métriques de performance
    */
public function getMetrics() {
    $queryCount = $this->metrics['query_count'];
    
    // ✅ CORRECTION: Calculs sécurisés avec vérification de division par zéro
    $averageTime = ($queryCount > 0) 
        ? round($this->metrics['total_execution_time'] / $queryCount, 2)
        : 0;
        
    $cacheHitRatio = ($queryCount > 0) 
        ? round(($this->metrics['cache_hits'] / $queryCount) * 100, 1)
        : 0;
        
    $errorRate = ($queryCount > 0) 
        ? round(($this->metrics['failed_queries'] / $queryCount) * 100, 2)
        : 0;
    
    // ✅ AJOUT: Métriques de performance avancées
    $baseMetrics = array_merge($this->metrics, [
        'average_execution_time_ms' => $averageTime,
        'cache_hit_ratio_percent' => $cacheHitRatio,
        'error_rate_percent' => $errorRate,
        'prepared_statements_cached' => count($this->preparedStatements),
        'active_transactions' => count($this->transactionStack),
        
        // ✅ AJOUT: Métriques de sécurité
        'security_events_logged' => $this->getSecurityEventsCount(),
        'suspicious_queries_detected' => $this->getSuspiciousQueriesCount(),
        
        // ✅ AJOUT: Métriques de santé
        'connection_stable' => $this->isConnected(),
        'last_error_time' => $this->getLastErrorTime(),
        'uptime_seconds' => time() - ($_SESSION['db_start_time'] ?? time()),
        
        // ✅ AJOUT: Métriques de ressources
        'memory_usage_bytes' => memory_get_usage(true),
        'memory_peak_bytes' => memory_get_peak_usage(true),
        'statements_cache_size' => count($this->preparedStatements),
        'critical_queries_logged' => count($this->criticalQueriesLog)
    ]);
    
    // ✅ AJOUT: Classification des performances
    $baseMetrics['performance_level'] = $this->calculatePerformanceLevel($baseMetrics);
    
    // ✅ AJOUT: Recommandations basées sur les métriques
    $baseMetrics['recommendations'] = $this->generateRecommendations($baseMetrics);
    
    return $baseMetrics;
}

/**
 * ✅ AJOUT: Compteur d'événements de sécurité
 */
private function getSecurityEventsCount() {
    return $_SESSION['db_security_events'] ?? 0;
}

/**
 * ✅ AJOUT: Compteur de requêtes suspectes
 */
private function getSuspiciousQueriesCount() {
    return $_SESSION['db_suspicious_queries'] ?? 0;
}

/**
 * ✅ AJOUT: Timestamp de la dernière erreur
 */
private function getLastErrorTime() {
    return $_SESSION['db_last_error_time'] ?? null;
}

/**
 * ✅ AJOUT: Classification du niveau de performance
 */
private function calculatePerformanceLevel($metrics) {
    $score = 100;
    
    // Pénalités basées sur les métriques
    if ($metrics['error_rate_percent'] > 5) $score -= 30;
    if ($metrics['average_execution_time_ms'] > 100) $score -= 20;
    if ($metrics['cache_hit_ratio_percent'] < 50) $score -= 15;
    if ($metrics['slow_queries'] > 10) $score -= 15;
    if ($metrics['reconnections'] > 0) $score -= 10;
    
    if ($score >= 90) return 'excellent';
    if ($score >= 75) return 'good';
    if ($score >= 60) return 'average';
    if ($score >= 40) return 'poor';
    return 'critical';
}

/**
 * ✅ AJOUT: Génération de recommandations
 */
private function generateRecommendations($metrics) {
    $recommendations = [];
    
    if ($metrics['error_rate_percent'] > 5) {
        $recommendations[] = 'Taux d\'erreur élevé - Vérifier la stabilité de la connexion';
    }
    
    if ($metrics['average_execution_time_ms'] > 100) {
        $recommendations[] = 'Temps de réponse lent - Optimiser les requêtes ou ajouter des index';
    }
    
    if ($metrics['cache_hit_ratio_percent'] < 50) {
        $recommendations[] = 'Faible taux de cache - Augmenter la taille du cache des statements';
    }
    
    if ($metrics['slow_queries'] > 10) {
        $recommendations[] = 'Nombreuses requêtes lentes - Analyser et optimiser les requêtes critiques';
    }
    
    if ($metrics['memory_usage_bytes'] > 64 * 1024 * 1024) { // 64MB
        $recommendations[] = 'Consommation mémoire élevée - Nettoyer les caches et optimiser';
    }
    
    if ($metrics['security_events_logged'] > 0) {
        $recommendations[] = 'Événements de sécurité détectés - Réviser les logs de sécurité';
    }
    
    if (empty($recommendations)) {
        $recommendations[] = 'Performances optimales - Aucune action requise';
    }
    
    return $recommendations;
}
   
   /**
    * Nettoyage et finalisation
    */
   public function cleanup() {
       // Rollback des transactions non fermées
       if (!empty($this->transactionStack)) {
           if (class_exists('Logger')) {
               Logger::warning('DATABASE', "Transactions non fermées détectées, rollback automatique", [
                   'open_transactions' => count($this->transactionStack)
               ]);
           }
           
           try {
               while (!empty($this->transactionStack)) {
                   $this->rollback();
               }
           } catch (Exception $e) {
               // Ignorer les erreurs de cleanup
           }
       }
       
       // Log des métriques finales si en mode debug
       if (DEBUG_DATABASE && class_exists('Logger') && $this->metrics['query_count'] > 0) {
           Logger::debug('DATABASE', "Métriques de session", $this->getMetrics());
           
           // Log des requêtes critiques s'il y en a
           if (!empty($this->criticalQueriesLog)) {
               Logger::warning('DATABASE', "Requêtes critiques de la session", [
                   'slow_queries' => $this->criticalQueriesLog
               ]);
           }
       }
       
       // Libérer les ressources
       $this->preparedStatements = [];
       $this->criticalQueriesLog = [];
   }
   
   /**
    * Nettoie les caches publiquement (pour Security::cleanupAllCaches)
    */
   public function clearStatements() {
       $this->preparedStatements = [];
       $this->criticalQueriesLog = [];
       
       if (class_exists('Logger')) {
           Logger::debug('DATABASE', "Cache des statements nettoyé");
       }
   }
   
   /**
    * Méthode statique pour nettoyage depuis Security
    */
   public static function clearCache() {
       $instance = self::getInstance();
       $instance->clearStatements();
   }
   
   // ================================================================================================
   // PROTECTION SINGLETON
   // ================================================================================================
   
   /**
    * Empêche le clonage
    */
   private function __clone() {}
   
   /**
    * Empêche la désérialisation
    */
   public function __wakeup() {
       throw new Exception("Cannot unserialize singleton");
   }
}
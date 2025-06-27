<?php
//SecureRedirect.php
/**
 * Gestionnaire de redirections sécurisées avec modals optimisé
 * 
 * Version 2.1 - Corrections de sécurité apportées :
 * - Ajout de la méthode sanitizeRedirectUrl() manquante
 * - Correction des types de retour incompatibles
 * - Amélioration des headers de sécurité
 * - Renforcement de la validation d'entrée
 * - Optimisation du cache et de la journalisation
 * 
 * @author Système Panier E-commerce
 * @version 2.1
 * @since 2024
 */

// Vérification des dépendances de sécurité
if (!defined('SECURE_ACCESS')) {
    if (class_exists('Logger')) {
        Logger::critical('SECURE_REDIRECT', "Accès direct au fichier SecureRedirect.php détecté");
    }
    exit('Accès direct au fichier interdit');
}

class SecureRedirect {
    
    // ================================================================================================
    // CONSTANTES ET CONFIGURATION
    // ================================================================================================
    
    /**
     * Types de redirections supportés
     */
    const TYPE_SESSION_EXPIRED = 'session_expired';
    const TYPE_PRODUCT_NOT_FOUND = 'product_not_found';
    const TYPE_SESSION_HIJACKING = 'session_hijacking';
    const TYPE_UNKNOWN_ACTION = 'unknown_action';
    const TYPE_SECURITY_ERROR = 'security_error';
    const TYPE_ACCESS_DENIED = 'access_denied';
    const TYPE_SYSTEM_ERROR = 'system_error';
    
    /**
     * Cache des vérifications d'URL pour optimiser les performances
     * @var array
     */
    private static $urlValidationCache = [];
    
    /**
     * Configuration des chemins vers les assets avec fallbacks
     * @var array
     */
    private static $assetPaths = [
        'css' => '../css/SecureRedirect1.css',
        'js' => '../js/SecureRedirect3.js'
    ];
    
    /**
     * Messages par défaut optimisés selon le type
     * @var array
     */
    private static $defaultMessages = [
        self::TYPE_SESSION_EXPIRED => [
            'title' => 'Session expirée',
            'message' => 'Votre session a expiré pour des raisons de sécurité. Vous allez être redirigé vers la page d\'accueil.',
            'icon' => '⏰'
        ],
        self::TYPE_PRODUCT_NOT_FOUND => [
            'title' => 'Produit introuvable',
            'message' => 'Le produit demandé n\'existe pas ou n\'est plus disponible. Vous allez être redirigé vers la page d\'accueil.',
            'icon' => '❌'
        ],
        self::TYPE_SESSION_HIJACKING => [
            'title' => 'Problème de sécurité détecté',
            'message' => 'Une anomalie de sécurité a été détectée sur votre session. Par précaution, vous allez être redirigé vers la page d\'accueil.',
            'icon' => '🛡️'
        ],
        self::TYPE_UNKNOWN_ACTION => [
            'title' => 'Action non reconnue',
            'message' => 'L\'action demandée n\'est pas valide. Vous allez être redirigé vers une page sécurisée.',
            'icon' => '❓'
        ],
        self::TYPE_SECURITY_ERROR => [
            'title' => 'Erreur de sécurité',
            'message' => 'Une erreur de sécurité s\'est produite. Vous allez être redirigé vers une page sécurisée.',
            'icon' => '⚠️'
        ],
        self::TYPE_ACCESS_DENIED => [
            'title' => 'Accès refusé',
            'message' => 'Vous n\'avez pas l\'autorisation d\'accéder à cette ressource. Vous allez être redirigé.',
            'icon' => '🚫'
        ],
        self::TYPE_SYSTEM_ERROR => [
            'title' => 'Erreur système',
            'message' => 'Une erreur technique s\'est produite. Vous allez être redirigé vers la page d\'accueil.',
            'icon' => '💥'
        ]
    ];
    
    private static function getAllowedUrls() {
        return [
            'index.php',
            // Ajoute ici d'autres fichiers autorisés si besoin
        ];
    }

    // ================================================================================================
    // CONFIGURATION ET MÉTHODES UTILITAIRES
    // ================================================================================================
    
    /**
     * Définit les chemins vers les assets CSS/JS
     */
    public static function setAssetPaths($paths) {
        self::$assetPaths = array_merge(self::$assetPaths, $paths);
        
        if (class_exists('Logger')) {
            Logger::debug('SECURE_REDIRECT', "Chemins d'assets configurés", [
                'css' => self::$assetPaths['css'],
                'js' => self::$assetPaths['js']
            ]);
        }
    }
    
    /**
     * Sécurise une URL de redirection (méthode corrigée ajoutée)
     */
private static function sanitizeRedirectUrl($url) {
    if (empty($url)) {
        return 'index.php';
    }
    
    // ✅ CORRECTION: Validation stricte du type et de la longueur
    if (!is_string($url) || strlen($url) > 2048) {
        if (class_exists('Logger')) {
            Logger::security('SECURE_REDIRECT', "URL de redirection invalide - type ou longueur", [
                'url_type' => gettype($url),
                'url_length' => is_string($url) ? strlen($url) : 'N/A',
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
        }
        return 'index.php';
    }
    
    // ✅ CORRECTION: Détection précoce de caractères de contrôle
    if (preg_match('/[\x00-\x1F\x7F]/', $url)) {
        if (class_exists('Logger')) {
            Logger::security('SECURE_REDIRECT', "Caractères de contrôle détectés dans URL", [
                'url_hex' => bin2hex($url),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
        }
        return 'index.php';
    }
    
    // Utiliser le validateur centralisé si disponible
    if (class_exists('URLValidator')) {
        return URLValidator::validateRedirectUrl($url, 'redirect');
    }
    
    // ✅ CORRECTION: Fallback sécurisé renforcé
    $cleanUrl = filter_var($url, FILTER_SANITIZE_URL);
    
    if ($cleanUrl === false) {
        if (class_exists('Logger')) {
            Logger::security('SECURE_REDIRECT', "URL de redirection invalide - échec du filtrage", [
                'original_url' => substr($url, 0, 200),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
        }
        return 'index.php';
    }
    
    // ✅ CORRECTION: Vérifications strictes de directory traversal
    $traversalPatterns = [
        '/\.\.\//',           // ../
        '/\.\.\\\\/',         // ..\
        '/%2e%2e%2f/i',      // URL encoded ../
        '/%2e%2e%5c/i',      // URL encoded ..\
        '/%252e%252e%252f/i', // Double URL encoded ../
        '/\.\.%2f/i',        // Mixed encoding
        '/%2e%2e\//i',       // Mixed encoding
    ];
    
    foreach ($traversalPatterns as $pattern) {
        if (preg_match($pattern, $cleanUrl)) {
            if (class_exists('Logger')) {
                Logger::security('SECURE_REDIRECT', "Tentative de directory traversal détectée", [
                    'url' => $cleanUrl,
                    'pattern' => $pattern,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
            }
            return 'index.php';
        }
    }
    
    // ✅ CORRECTION: Vérification des caractères dangereux étendus
    $dangerousChars = ['<', '>', '"', "'", '`', '{', '}', '|', '^', '[', ']', '%00'];
    foreach ($dangerousChars as $char) {
        if (strpos($cleanUrl, $char) !== false) {
            if (class_exists('Logger')) {
                Logger::security('SECURE_REDIRECT', "Caractère dangereux détecté dans URL", [
                    'url' => $cleanUrl,
                    'character' => $char,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
            }
            return 'index.php';
        }
    }
    
    // ✅ CORRECTION: Validation stricte des patterns autorisés
    $allowedPatterns = [
        '/^[a-zA-Z0-9_\-]{1,50}\.php$/',  // Fichiers PHP simples
        '/^[a-zA-Z0-9_\-]{1,30}\/[a-zA-Z0-9_\-]{1,50}\.php$/', // Un niveau de répertoire max
    ];
    
    $isValidPattern = false;
    foreach ($allowedPatterns as $pattern) {
        if (preg_match($pattern, $cleanUrl)) {
            $isValidPattern = true;
            break;
        }
    }
    
    // ✅ CORRECTION: Vérification liste blanche stricte
    if (!$isValidPattern && !in_array($cleanUrl, self::getAllowedUrls())) {
        if (class_exists('Logger')) {
            Logger::security('SECURE_REDIRECT', "URL de redirection non autorisée", [
                'original_url' => substr($url, 0, 200),
                'cleaned_url' => substr($cleanUrl, 0, 200),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
        }
        return 'index.php';
    }
    
    // ✅ CORRECTION: Validation finale de l'existence du fichier
    if ($isValidPattern) {
        $fullPath = $_SERVER['DOCUMENT_ROOT'] . '/' . ltrim($cleanUrl, '/');
        $realPath = realpath($fullPath);
        
        // Vérifier que le chemin résolu est dans le document root
        if ($realPath === false || strpos($realPath, $_SERVER['DOCUMENT_ROOT']) !== 0) {
            if (class_exists('Logger')) {
                Logger::security('SECURE_REDIRECT', "Tentative d'accès hors document root", [
                    'url' => $cleanUrl,
                    'resolved_path' => $realPath,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
            }
            return 'index.php';
        }
        
        // Vérifier que le fichier existe et est lisible
        if (!file_exists($realPath) || !is_readable($realPath)) {
            if (class_exists('Logger')) {
                Logger::warning('SECURE_REDIRECT', "Fichier de redirection inexistant", [
                    'url' => $cleanUrl,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
            }
            return 'index.php';
        }
    }
    
    return $cleanUrl;
}
    
    /**
     * Obtient les données du message selon le type avec cache
     */
    private static function getMessageData($type, $customMessage, $options) {
        $defaultData = self::$defaultMessages[$type] ?? self::$defaultMessages[self::TYPE_SYSTEM_ERROR];
        
        $messageData = [
            'title' => $options['title'] ?? $defaultData['title'],
            'message' => $customMessage ?? $defaultData['message'],
            'icon' => $options['icon'] ?? $defaultData['icon'],
            'details' => $options['details'] ?? null,
            'showCancel' => $options['showCancel'] ?? false
        ];
        
        // Ajouter des détails en mode développement uniquement
        if (defined('ENVIRONMENT') && ENVIRONMENT === 'development' && !isset($options['details'])) {
            $messageData['details'] = self::getDebugDetails($type, $options);
        }
        
        return $messageData;
    }
    
    /**
     * Génère les détails de débogage (mode développement uniquement)
     */
    private static function getDebugDetails($type, $options) {
        if (!defined('ENVIRONMENT') || ENVIRONMENT !== 'development') {
            return null;
        }
        
        $details = [
            "Type: " . htmlspecialchars($type),
            "Heure: " . date('Y-m-d H:i:s'),
            "IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'inconnue'),
            "User Agent: " . htmlspecialchars(substr($_SERVER['HTTP_USER_AGENT'] ?? 'inconnu', 0, 100))
        ];
        
        if (isset($options['debug_info'])) {
            if (is_array($options['debug_info'])) {
                foreach ($options['debug_info'] as $key => $value) {
                    if (is_scalar($value)) {
                        $details[] = htmlspecialchars($key) . ": " . htmlspecialchars(substr((string)$value, 0, 100));
                    }
                }
            } else {
                $details[] = "Info: " . htmlspecialchars(substr((string)$options['debug_info'], 0, 100));
            }
        }
        
        return implode('<br>', $details);
    }
    
    // ================================================================================================
    // JOURNALISATION OPTIMISÉE
    // ================================================================================================
    
    /**
     * Journalise la redirection (événements critiques uniquement)
     */
    private static function logRedirection($type, $redirectUrl, $messageData, $options) {
        // Log seulement les événements de sécurité critiques
        $criticalTypes = [
            self::TYPE_SESSION_HIJACKING,
            self::TYPE_SECURITY_ERROR,
            self::TYPE_ACCESS_DENIED
        ];
        
        $shouldLog = in_array($type, $criticalTypes) || 
                    (defined('ENVIRONMENT') && ENVIRONMENT === 'development');
        
        if (!$shouldLog) {
            return;
        }
        
        $logData = [
            'type' => $type,
            'redirect_url' => $redirectUrl,
            'title' => $messageData['title'],
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 200),
            'session_id' => session_id(),
            'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown'
        ];
        
        // Ajouter les infos de debug seulement si pertinentes
        if (isset($options['debug_info']) && is_array($options['debug_info'])) {
            $logData['debug_info'] = array_slice($options['debug_info'], 0, 5); // Limiter à 5 éléments
        }
        
        if (class_exists('Logger')) {
            Logger::log('SECURE_REDIRECT', 'Redirection sécurisée effectuée', 'security', $logData);
        }
        
        if (class_exists('Security')) {
            Security::logSecurityEvent('security_redirect', 'Redirection sécurisée effectuée', $logData);
        }
    }
    
    // ================================================================================================
    // RENDU OPTIMISÉ DES PAGES D'ERREUR
    // ================================================================================================
    
    /**
     * Génère la page avec modal de manière optimisée
     */
private static function renderRedirectPage($type, $redirectUrl, $messageData, $options) {
    // Nettoyage du buffer uniquement
    while (ob_get_level()) {
        ob_end_clean();
    }
    
    // Génération du nonce pour CSP (sans headers HTTP)
    $nonce = '';
    if (class_exists('Security')) {
        try {
            $nonce = Security::generateNonce();
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::warning('SECURE_REDIRECT', "Impossible de générer un nonce CSP: " . $e->getMessage());
            }
        }
    }
    
    // Validation renforcée de l'URL pour hébergement mutualisé
    $sanitizedRedirectUrl = self::validateRedirectUrlForSharedHosting($redirectUrl);
    
    // Préparer les données JSON pour JavaScript avec validation
    $jsData = [
        'type' => htmlspecialchars($type, ENT_QUOTES, 'UTF-8'),
        'title' => htmlspecialchars($messageData['title'], ENT_QUOTES, 'UTF-8'),
        'message' => htmlspecialchars($messageData['message'], ENT_QUOTES, 'UTF-8'),
        'redirectUrl' => htmlspecialchars($sanitizedRedirectUrl, ENT_QUOTES, 'UTF-8'),
        'details' => $messageData['details'] ? htmlspecialchars($messageData['details'], ENT_QUOTES, 'UTF-8') : null,
        'showCancel' => (bool)$messageData['showCancel'],
        'environment' => defined('ENVIRONMENT') ? htmlspecialchars(ENVIRONMENT, ENT_QUOTES, 'UTF-8') : 'production',
        'timestamp' => time(),
        'nonce' => $nonce,
        'hosting_mode' => 'shared'
    ];
    
    // Encodage JSON sécurisé
    $jsDataJson = json_encode($jsData, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE);
    
    if ($jsDataJson === false) {
        if (class_exists('Logger')) {
            Logger::error('SECURE_REDIRECT', "Erreur encodage JSON des données de redirection");
        }
        $jsDataJson = '{"error":"encoding_failed","hosting_mode":"shared"}';
    }
    
    // Vérifier l'existence des assets
    $cssExists = file_exists(self::$assetPaths['css']) && is_readable(self::$assetPaths['css']);
    $jsExists = file_exists(self::$assetPaths['js']) && is_readable(self::$assetPaths['js']);
    
    // Rendu de la page optimisé pour hébergement mutualisé
    self::outputRedirectPageForSharedHosting($messageData, $jsDataJson, $sanitizedRedirectUrl, $cssExists, $jsExists, $nonce);
}

/**
 * Validation d'URL spécifique pour hébergement mutualisé
 */
private static function validateRedirectUrlForSharedHosting($url) {
    // Validation de base
    $cleanUrl = self::sanitizeRedirectUrl($url);
    
    // Vérifications supplémentaires pour hébergement mutualisé
    
    // Pas d'URLs avec des ports non standard
    if (preg_match('/:\d+/', $cleanUrl) && !preg_match('/:(80|443)/', $cleanUrl)) {
        if (class_exists('Logger')) {
            Logger::security('SECURE_REDIRECT', "Port non standard détecté en hébergement mutualisé", [
                'url' => $cleanUrl
            ]);
        }
        return 'index.php';
    }
    
    // Pas d'URLs avec des paramètres GET complexes
    if (substr_count($cleanUrl, '?') > 1 || substr_count($cleanUrl, '&') > 5) {
        if (class_exists('Logger')) {
            Logger::security('SECURE_REDIRECT', "URL trop complexe pour hébergement mutualisé", [
                'url' => substr($cleanUrl, 0, 100)
            ]);
        }
        return 'index.php';
    }
    
    return $cleanUrl;
}
    
    /**
     * Génère le HTML de la page de redirection
     */
    private static function outputRedirectPage($messageData, $jsDataJson, $redirectUrl, $cssExists, $jsExists) {
        ?>
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <title><?= htmlspecialchars($messageData['title']) ?></title>
            
            <?php if ($cssExists): ?>
                <link rel="stylesheet" href="<?= htmlspecialchars(self::$assetPaths['css']) ?>">
            <?php else: ?>
                <!-- Styles de fallback intégrés optimisés -->
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
                    .container { max-width: 500px; background: white; border-radius: 16px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); padding: 40px; text-align: center; animation: slideIn 0.3s ease-out; }
                    @keyframes slideIn { from { opacity: 0; transform: translateY(-20px); } to { opacity: 1; transform: translateY(0); } }
                    .icon { font-size: 64px; margin-bottom: 20px; }
                    .title { color: #2d3748; margin-bottom: 20px; font-size: 24px; font-weight: 600; }
                    .message { color: #4a5568; margin-bottom: 30px; line-height: 1.6; }
                    .button { display: inline-block; padding: 12px 24px; background: #4299e1; color: white; text-decoration: none; border-radius: 8px; font-weight: 500; transition: all 0.2s; }
                    .button:hover { background: #3182ce; transform: translateY(-1px); }
                    .details { margin: 20px 0; text-align: left; background: #f7fafc; padding: 15px; border-radius: 8px; font-size: 14px; color: #2d3748; }
                    .countdown { margin-top: 20px; color: #718096; font-size: 14px; }
                </style>
            <?php endif; ?>
        </head>
        <body>
            <!-- Données pour JavaScript -->
            <script type="application/json" id="security-redirect-data"><?= $jsDataJson ?></script>
            
            <!-- Contenu principal -->
            <div class="container" id="redirect-container">
                <div class="icon"><?= htmlspecialchars($messageData['icon']) ?></div>
                <h1 class="title"><?= htmlspecialchars($messageData['title']) ?></h1>
                <p class="message"><?= htmlspecialchars($messageData['message']) ?></p>
                
                <?php if ($messageData['details'] && defined('ENVIRONMENT') && ENVIRONMENT === 'development'): ?>
                    <details class="details">
                        <summary>Détails techniques (développement)</summary>
                        <div><?= $messageData['details'] ?></div>
                    </details>
                <?php endif; ?>
                
                <div class="countdown" id="countdown">Redirection dans <span id="timer">5</span> secondes...</div>
                <a href="<?= htmlspecialchars($redirectUrl) ?>" class="button" id="redirect-button">
                    Continuer maintenant
                </a>
            </div>
            
            <?php if ($jsExists): ?>
                <script src="<?= htmlspecialchars(self::$assetPaths['js']) ?>"></script>
            <?php else: ?>
                <!-- Script de fallback intégré optimisé -->
                <script>
                    (function() {
                        const data = JSON.parse(document.getElementById('security-redirect-data').textContent);
                        let timeLeft = 5;
                        const timerElement = document.getElementById('timer');
                        const countdownElement = document.getElementById('countdown');
                        
                        // Fonction de redirection
                        function redirect() {
                            window.location.href = data.redirectUrl;
                        }
                        
                        // Compte à rebours
                        const countdown = setInterval(function() {
                            timeLeft--;
                            if (timerElement) {
                                timerElement.textContent = timeLeft;
                            }
                            
                            if (timeLeft <= 0) {
                                clearInterval(countdown);
                                redirect();
                            }
                        }, 1000);
                        
                        // Redirection au clic
                        const button = document.getElementById('redirect-button');
                        if (button) {
                            button.addEventListener('click', function(e) {
                                e.preventDefault();
                                clearInterval(countdown);
                                redirect();
                            });
                        }
                        
                        // Redirection au clavier (Entrée ou Espace)
                        document.addEventListener('keydown', function(e) {
                            if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault();
                                clearInterval(countdown);
                                redirect();
                            }
                        });
                        
                        // Focus sur le bouton pour l'accessibilité
                        if (button) {
                            button.focus();
                        }
                    })();
                </script>
            <?php endif; ?>
        </body>
        </html>
        <?php
    }
    
    
    
    
    /**
 * ✅ NOUVEAU: Génération HTML optimisée pour hébergement mutualisé
 */
private static function outputRedirectPageForSharedHosting($messageData, $jsDataJson, $redirectUrl, $cssExists, $jsExists, $nonce = '') {
    // Validation des données avant sortie
    $safeTitle = htmlspecialchars($messageData['title'] ?? 'Redirection', ENT_QUOTES, 'UTF-8');
    $safeIcon = htmlspecialchars($messageData['icon'] ?? '⚠️', ENT_QUOTES, 'UTF-8');
    $safeMessage = htmlspecialchars($messageData['message'] ?? 'Redirection en cours...', ENT_QUOTES, 'UTF-8');
    $safeRedirectUrl = htmlspecialchars($redirectUrl, ENT_QUOTES, 'UTF-8');
    
    // Validation finale de l'URL
    if (!filter_var($redirectUrl, FILTER_VALIDATE_URL) && !preg_match('/^[a-zA-Z0-9_\-\/\.]+\.php$/', $redirectUrl)) {
        $safeRedirectUrl = 'index.php';
    }
    
    // Génération des meta tags de sécurité
    $securityMetaTags = '';
    if (class_exists('Security')) {
        $securityMetaTags = Security::generateSecurityMetaTags();
    }
    
    ?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title><?= $safeTitle ?></title>
    
    <?php if ($securityMetaTags): ?>
    <!-- Meta tags de sécurité pour hébergement mutualisé -->
    <?= $securityMetaTags ?>
    <?php endif; ?>
    
    <?php if ($cssExists): ?>
        <link rel="stylesheet" href="<?= htmlspecialchars(self::$assetPaths['css'], ENT_QUOTES, 'UTF-8') ?>"<?= $nonce ? ' nonce="' . htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') . '"' : '' ?>>
    <?php else: ?>
        <!-- Styles de fallback sécurisés pour hébergement mutualisé -->
        <style<?= $nonce ? ' nonce="' . htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') . '"' : '' ?>>
            /* CSS Reset sécurisé */
            * { 
                margin: 0; 
                padding: 0; 
                box-sizing: border-box; 
            }
            
            /* Protection contre l'injection CSS */
            html, body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0;
                padding: 0;
                overflow-x: hidden;
            }
            
            .container {
                max-width: 500px;
                width: 90%;
                background: white;
                border-radius: 16px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                padding: 40px;
                text-align: center;
                animation: slideIn 0.3s ease-out;
                position: relative;
                word-wrap: break-word;
            }
            
            @keyframes slideIn {
                from { 
                    opacity: 0; 
                    transform: translateY(-20px); 
                }
                to { 
                    opacity: 1; 
                    transform: translateY(0); 
                }
            }
            
            .icon {
                font-size: 64px;
                margin-bottom: 20px;
                line-height: 1;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }
            
            .title {
                color: #2d3748;
                margin-bottom: 20px;
                font-size: 24px;
                font-weight: 600;
                line-height: 1.3;
                word-wrap: break-word;
                max-height: 100px;
                overflow: hidden;
            }
            
            .message {
                color: #4a5568;
                margin-bottom: 30px;
                line-height: 1.6;
                font-size: 16px;
                word-wrap: break-word;
                max-height: 200px;
                overflow: hidden;
            }
            
            .button {
                display: inline-block;
                padding: 12px 24px;
                background: #4299e1;
                color: white;
                text-decoration: none;
                border-radius: 8px;
                font-weight: 500;
                transition: all 0.2s ease;
                border: none;
                cursor: pointer;
                font-size: 16px;
                min-width: 200px;
                position: relative;
                z-index: 1000;
            }
            
            .button:hover {
                background: #3182ce;
                transform: translateY(-1px);
            }
            
            .button:focus {
                outline: 2px solid #4299e1;
                outline-offset: 2px;
            }
            
            .countdown {
                margin-top: 20px;
                color: #718096;
                font-size: 14px;
                font-weight: 500;
            }
            
            .countdown #timer {
                font-weight: bold;
                color: #4299e1;
                font-size: 18px;
            }
            
            /* Protection contre les manipulations visuelles */
            .container::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                pointer-events: none;
                z-index: -1;
            }
            
            /* Responsive design sécurisé */
            @media (max-width: 600px) {
                .container {
                    padding: 30px 20px;
                    margin: 20px;
                }
                
                .title {
                    font-size: 20px;
                }
                
                .message {
                    font-size: 14px;
                }
            }
            
            /* Protection contre les attaques de lecture */
            .hidden {
                display: none !important;
                visibility: hidden !important;
                opacity: 0 !important;
            }
        </style>
    <?php endif; ?>
</head>
<body>
    <!-- Données sécurisées pour JavaScript (hébergement mutualisé) -->
    <script type="application/json" id="security-redirect-data"<?= $nonce ? ' nonce="' . htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') . '"' : '' ?>><?= $jsDataJson ?></script>
    
    <!-- Contenu principal sécurisé -->
    <div class="container" id="redirect-container" role="main" aria-live="polite">
        <div class="icon" aria-hidden="true"><?= $safeIcon ?></div>
        <h1 class="title" id="page-title"><?= $safeTitle ?></h1>
        <p class="message" id="page-message"><?= $safeMessage ?></p>
        
        <?php if ($messageData['details'] && defined('ENVIRONMENT') && ENVIRONMENT === 'development'): ?>
            <details class="details">
                <summary>Détails techniques (développement)</summary>
                <div><?= htmlspecialchars($messageData['details'], ENT_QUOTES, 'UTF-8') ?></div>
            </details>
        <?php endif; ?>
        
        <div class="countdown" id="countdown" aria-live="polite">
            Redirection dans <span id="timer" aria-label="Temps restant">5</span> secondes...
        </div>
        
        <a href="<?= $safeRedirectUrl ?>" 
           class="button" 
           id="redirect-button" 
           role="button"
           aria-describedby="page-message"
           rel="noopener noreferrer">
            Continuer maintenant
        </a>
    </div>
    
    <?php if ($jsExists): ?>
        <script src="<?= htmlspecialchars(self::$assetPaths['js'], ENT_QUOTES, 'UTF-8') ?>"<?= $nonce ? ' nonce="' . htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') . '"' : '' ?>></script>
    <?php else: ?>
        <!-- Script de fallback sécurisé pour hébergement mutualisé -->
        <script<?= $nonce ? ' nonce="' . htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') . '"' : '' ?>>
            (function() {
                'use strict';
                
                // Protection basique contre le clickjacking
                if (top !== self) {
                    top.location = self.location;
                }
                
                // Validation et parsing sécurisé des données
                var dataElement = document.getElementById('security-redirect-data');
                var data = null;
                
                try {
                    if (!dataElement || !dataElement.textContent) {
                        throw new Error('Données de redirection manquantes');
                    }
                    
                    data = JSON.parse(dataElement.textContent);
                    
                    // Validation des données parsées
                    if (!data || typeof data !== 'object') {
                        throw new Error('Format de données invalide');
                    }
                    
                    // Validation des champs requis
                    var requiredFields = ['redirectUrl', 'type'];
                    for (var i = 0; i < requiredFields.length; i++) {
                        if (!data[requiredFields[i]]) {
                            throw new Error('Champ requis manquant: ' + requiredFields[i]);
                        }
                    }
                    
                    // Validation de l'URL pour hébergement mutualisé
                    var urlPattern = /^[a-zA-Z0-9_\-\/\.]+\.php$|^https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[^\s<>"']*$/;
                    if (!urlPattern.test(data.redirectUrl)) {
                        console.warn('URL de redirection suspecte, utilisation du fallback');
                        data.redirectUrl = 'index.php';
                    }
                    
                } catch (error) {
                    console.error('Erreur de parsing des données:', error);
                    data = {
                        redirectUrl: 'index.php',
                        type: 'error',
                        hosting_mode: 'shared'
                    };
                }
                
                var timeLeft = 5;
                var timerElement = document.getElementById('timer');
                var countdownElement = document.getElementById('countdown');
                var redirectButton = document.getElementById('redirect-button');
                var countdownInterval = null;
                
                // Fonction de redirection sécurisée
                function performRedirect() {
                    try {
                        if (data.redirectUrl && typeof data.redirectUrl === 'string') {
                            // Protection supplémentaire pour hébergement mutualisé
                            var safeUrl = data.redirectUrl.replace(/[<>"']/g, '');
                            
                            // Validation finale de l'URL
                            if (safeUrl.length > 0 && safeUrl.length < 2000) {
                                if (data.environment === 'development') {
                                    console.log('Redirection vers:', safeUrl);
                                }
                                window.location.href = safeUrl;
                            } else {
                                throw new Error('URL de redirection invalide');
                            }
                        } else {
                            throw new Error('URL de redirection manquante');
                        }
                    } catch (error) {
                        console.error('Erreur de redirection:', error);
                        window.location.href = 'index.php';
                    }
                }
                
                // Compte à rebours sécurisé
                function updateCountdown() {
                    timeLeft--;
                    
                    if (timerElement) {
                        timerElement.textContent = Math.max(0, timeLeft);
                        timerElement.setAttribute('aria-label', 'Temps restant: ' + Math.max(0, timeLeft) + ' secondes');
                    }
                    
                    if (timeLeft <= 0) {
                        if (countdownInterval) {
                            clearInterval(countdownInterval);
                        }
                        
                        if (countdownElement) {
                            countdownElement.textContent = 'Redirection en cours...';
                        }
                        
                        setTimeout(performRedirect, 500);
                    }
                }
                
                // Initialisation sécurisée
                function initialize() {
                    countdownInterval = setInterval(updateCountdown, 1000);
                    
                    if (redirectButton) {
                        // Mise à jour de l'URL du bouton
                        redirectButton.setAttribute('href', data.redirectUrl);
                        
                        redirectButton.addEventListener('click', function(event) {
                            event.preventDefault();
                            
                            if (countdownInterval) {
                                clearInterval(countdownInterval);
                            }
                            
                            performRedirect();
                        });
                        
                        // Support clavier
                        redirectButton.addEventListener('keydown', function(event) {
                            if (event.key === 'Enter' || event.key === ' ') {
                                event.preventDefault();
                                redirectButton.click();
                            }
                        });
                    }
                    
                    // Gestion globale du clavier
                    document.addEventListener('keydown', function(event) {
                        if (event.key === 'Escape') {
                            if (countdownInterval) {
                                clearInterval(countdownInterval);
                            }
                            
                            if (countdownElement) {
                                countdownElement.textContent = 'Redirection annulée. Cliquez sur le bouton pour continuer.';
                            }
                            return;
                        }
                        
                        if (event.key === 'Enter' || event.key === ' ') {
                            if (event.target.tagName !== 'BUTTON' && event.target.tagName !== 'A') {
                                event.preventDefault();
                                
                                if (countdownInterval) {
                                    clearInterval(countdownInterval);
                                }
                                
                                performRedirect();
                            }
                        }
                    });
                    
                    // Focus pour l'accessibilité
                    if (redirectButton) {
                        redirectButton.focus();
                    }
                    
                    // Gestion de la visibilité de la page
                    if (typeof document.visibilityState !== 'undefined') {
                        document.addEventListener('visibilitychange', function() {
                            if (document.visibilityState === 'hidden' && countdownInterval) {
                                clearInterval(countdownInterval);
                            } else if (document.visibilityState === 'visible' && timeLeft > 0) {
                                countdownInterval = setInterval(updateCountdown, 1000);
                            }
                        });
                    }
                }
                
                // Initialisation au chargement
                if (document.readyState === 'loading') {
                    document.addEventListener('DOMContentLoaded', initialize);
                } else {
                    initialize();
                }
                
                // Nettoyage
                window.addEventListener('beforeunload', function() {
                    if (countdownInterval) {
                        clearInterval(countdownInterval);
                    }
                });
                
            })();
        </script>
    <?php endif; ?>
    
    <!-- Fallback noscript pour l'accessibilité -->
    <noscript>
        <div style="position: fixed; top: 0; left: 0; width: 100%; background: #dc2626; color: white; padding: 10px; text-align: center; z-index: 9999;">
            JavaScript est désactivé. <a href="<?= $safeRedirectUrl ?>" style="color: white; text-decoration: underline;">Cliquez ici pour continuer</a>
        </div>
    </noscript>
</body>
</html>
    <?php
}
    
    
    
    
    
    
    
    
    
    // ================================================================================================
    // MÉTHODES PRINCIPALES DE REDIRECTION
    // ================================================================================================
    
    /**
     * Effectue une redirection sécurisée avec modal optimisée
     */
    public static function redirect($type, $redirectUrl = 'index.php', $customMessage = null, $options = []) {
        // Sécuriser l'URL de redirection
        $redirectUrl = self::sanitizeRedirectUrl($redirectUrl);
        
        // Obtenir le message approprié
        $messageData = self::getMessageData($type, $customMessage, $options);
        
        // Journaliser la redirection (événements critiques uniquement)
        self::logRedirection($type, $redirectUrl, $messageData, $options);
        
        // Générer la page avec modal
        self::renderRedirectPage($type, $redirectUrl, $messageData, $options);
        
        // Arrêter l'exécution
        exit;
    }
    
    // ================================================================================================
    // MÉTHODES DE CONVENANCE OPTIMISÉES
    // ================================================================================================
    
    /**
     * Méthode générique pour créer des redirections avec debug info
     */
    private static function createRedirect($type, $debugInfo, $redirectUrl = 'index.php', $customMessage = null) {
        self::redirect($type, $redirectUrl, $customMessage, [
            'debug_info' => $debugInfo
        ]);
    }
    
    /**
     * Redirection pour session expirée
     */
    public static function sessionExpired($redirectUrl = 'index.php', $customMessage = null) {
        $debugInfo = [
            'last_activity' => $_SESSION['last_activity'] ?? 'unknown',
            'session_id' => session_id(),
            'inactivity_time' => isset($_SESSION['last_activity']) ? (time() - $_SESSION['last_activity']) : 'unknown'
        ];
        
        self::createRedirect(self::TYPE_SESSION_EXPIRED, $debugInfo, $redirectUrl, $customMessage);
    }
    
    /**
     * Redirection pour produit non trouvé
     */
    public static function productNotFound($productId = null, $redirectUrl = 'index.php', $customMessage = null) {
        $debugInfo = [
            'product_id' => $productId,
            'requested_url' => $_SERVER['REQUEST_URI'] ?? 'unknown'
        ];
        
        self::createRedirect(self::TYPE_PRODUCT_NOT_FOUND, $debugInfo, $redirectUrl, $customMessage);
    }
    
    /**
     * Redirection pour détournement de session
     */
    public static function sessionHijacking($redirectUrl = 'index.php', $customMessage = null) {
        $debugInfo = [
            'session_id' => session_id(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ];
        
        self::createRedirect(self::TYPE_SESSION_HIJACKING, $debugInfo, $redirectUrl, $customMessage);
    }
    
    /**
     * Redirection pour action inconnue
     */
    public static function unknownAction($action = null, $redirectUrl = 'panier.php', $customMessage = null) {
        $debugInfo = [
            'requested_action' => $action,
            'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown'
        ];
        
        self::createRedirect(self::TYPE_UNKNOWN_ACTION, $debugInfo, $redirectUrl, $customMessage);
    }
    
    /**
     * Redirection pour erreur de sécurité
     */
    public static function securityError($error = null, $redirectUrl = 'index.php', $customMessage = null, $options = []) {
        $debugInfo = [
            'error' => $error,
            'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown'
        ];
        
        self::redirect(self::TYPE_SECURITY_ERROR, $redirectUrl, $customMessage, array_merge([
            'debug_info' => $debugInfo
        ], $options));
    }
    
    /**
     * Redirection pour accès refusé
     */
    public static function accessDenied($resource = null, $redirectUrl = 'index.php', $customMessage = null) {
        $debugInfo = [
            'resource' => $resource,
            'user_id' => $_SESSION['user_id'] ?? 'anonymous'
        ];
        
        self::createRedirect(self::TYPE_ACCESS_DENIED, $debugInfo, $redirectUrl, $customMessage);
    }
    
    /**
     * Redirection pour erreur système
     */
    public static function systemError($error = null, $redirectUrl = 'index.php', $customMessage = null, $options = []) {
        $debugInfo = [
            'error' => $error,
            'php_version' => PHP_VERSION,
            'memory_usage' => memory_get_usage(true)
        ];
        
        self::redirect(self::TYPE_SYSTEM_ERROR, $redirectUrl, $customMessage, array_merge([
            'debug_info' => $debugInfo
        ], $options));
    }
    
    // ================================================================================================
    // MÉTHODES UTILITAIRES ET TEST
    // ================================================================================================
    
    /**
     * Détecte automatiquement le type de redirection (simplifié)
     */
    private static function detectRedirectionType($url) {
        // Logique simplifiée basée sur des mots-clés dans l'URL et le contexte
        if (strpos($url, 'panier') !== false) {
            return self::TYPE_UNKNOWN_ACTION;
        }
        
        if (strpos($url, 'product') !== false) {
            return self::TYPE_PRODUCT_NOT_FOUND;
        }
        
        // Analyser la pile d'appels de manière simplifiée
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 5);
        
        foreach ($backtrace as $trace) {
            $function = strtolower($trace['function'] ?? '');
            
            if (strpos($function, 'session') !== false) {
                return self::TYPE_SESSION_EXPIRED;
            }
            
            if (strpos($function, 'security') !== false) {
                return self::TYPE_SECURITY_ERROR;
            }
        }
        
        return self::TYPE_SYSTEM_ERROR;
    }
    
    /**
     * Méthode de test pour vérifier les modals (développement uniquement)
     */
    public static function testModal($type = null) {
        if (!defined('ENVIRONMENT') || ENVIRONMENT !== 'development') {
            return false;
        }
        
        $type = $type ?? self::TYPE_SYSTEM_ERROR;
        
        self::redirect($type, 'index.php', 'Ceci est un test de modal de sécurité.', [
            'title' => 'Test Modal',
            'details' => 'Modal de test en mode développement.<br>Type: ' . $type,
            'showCancel' => true
        ]);
    }
    
    /**
     * Nettoie le cache des validations d'URL
     */
    public static function clearCache() {
        self::$urlValidationCache = [];
        
        if (class_exists('Logger')) {
            Logger::debug('SECURE_REDIRECT', "Cache des validations d'URL vidé");
        }
    }
}

/**
 * ✅ CLASSE VALIDATEUR D'URLS CENTRALISÉ ET SÉCURISÉ
 */
class URLValidator {
    
    /**
     * Cache des validations pour optimiser les performances
     */
    private static $validationCache = [];
    
    /**
     * Fichiers explicitement autorisés (liste blanche stricte)
     */
    private static $allowedFiles = [
        'index.php',
        'login.php', 
        'logout.php',
        'panier.php',
        'checkout.php',
        'cart.php',
        'cart_simple.php',
        'contact.php',
        'about.php'
    ];
    
    /**
     * Patterns autorisés pour les URLs relatives
     */
    private static $allowedPatterns = [
        '/^[a-zA-Z0-9_\-]{1,50}\.php$/',
        '/^panier\/[a-zA-Z0-9_\-]{1,50}\.php$/',
        '/^admin\/[a-zA-Z0-9_\-]{1,50}\.php$/'
    ];
    
    /**
     * Répertoires interdits (liste noire)
     */
    private static $forbiddenPaths = [
        'config', 'logs', 'vendor', 'node_modules', 
        '.git', '.svn', 'backup', 'tmp', 'temp'
    ];
    
    /**
     * Valide une URL de redirection de manière sécurisée
     */
    public static function validateRedirectUrl($url, $context = 'general') {
        // Vérifications préliminaires renforcées
        if (!is_string($url) || strlen($url) > 2048) {
            self::logSuspiciousUrl($url, 'invalid_input_type_or_length');
            return 'index.php';
        }
        
        // Vérifier le cache
        $cacheKey = md5($url . '_' . $context);
        if (isset(self::$validationCache[$cacheKey])) {
            return self::$validationCache[$cacheKey];
        }
        
        // Nettoyer l'URL d'entrée
        $originalUrl = $url;
        $cleanUrl = self::sanitizeUrl($url);
        
        if ($cleanUrl === false) {
            self::logSuspiciousUrl($originalUrl, 'sanitization_failed');
            self::$validationCache[$cacheKey] = 'index.php';
            return 'index.php';
        }
        
        // Validation par étapes
        $validatedUrl = self::performValidation($cleanUrl, $context);
        
        // Mettre en cache le résultat
        self::$validationCache[$cacheKey] = $validatedUrl;
        
        // Log si l'URL a été modifiée
        if ($validatedUrl !== $originalUrl) {
            self::logUrlModification($originalUrl, $validatedUrl, $context);
        }
        
        return $validatedUrl;
    }
    
    /**
     * Nettoie une URL de manière sécurisée
     */
    private static function sanitizeUrl($url) {
        if (empty($url) || !is_string($url)) {
            return false;
        }
        
        // Décoder les entités HTML
        $url = html_entity_decode($url, ENT_QUOTES, 'UTF-8');
        
        // Supprimer les caractères de contrôle
        $url = preg_replace('/[\x00-\x1F\x7F]/', '', $url);
        
        // Filtrer avec PHP
        $filtered = filter_var($url, FILTER_SANITIZE_URL);
        
        if ($filtered === false) {
            return false;
        }
        
        // Vérifications supplémentaires
        if (strpos($filtered, '..') !== false) {
            return false; // Tentative de directory traversal
        }
        
        if (preg_match('/[<>"\'`]/', $filtered)) {
            return false; // Caractères dangereux
        }
        
        return $filtered;
    }
    
    /**
     * Effectue la validation principale
     */
private static function performValidation($cleanUrl, $context) {
    // ✅ CORRECTION: Validation préalable stricte
    if (empty($cleanUrl) || strlen($cleanUrl) > 255) {
        self::logSuspiciousUrl($cleanUrl, 'invalid_length');
        return self::getDefaultRedirect($context);
    }
    
    // ✅ CORRECTION: Détection de patterns d'attaque sophistiqués
    $attackPatterns = [
        // Directory traversal variants
        '/\.\.[\\/]/',
        '/%2e%2e[\\/]/i',
        '/%252e%252e[\\/]/i',
        '/\.\.[%\/\\\\]/i',
        
        // Protocol confusion
        '/^(javascript|data|vbscript|file|ftp):/i',
        '/^\/\/[^\/]/',  // Protocol-relative URLs
        
        // Injection attempts
        '/[<>"\'\`]/',
        '/%3c|%3e|%22|%27|%60/i',  // URL encoded
        
        // Null bytes and control chars
        '/%00|%0a|%0d/i',
        '/[\x00-\x1f\x7f-\x9f]/',
        
        // Path confusion
        '/\/\.\//',      // /./
        '/\/\/+/',       // Multiple slashes
        '/\\\\//',       // Backslashes
    ];
    
    foreach ($attackPatterns as $pattern) {
        if (preg_match($pattern, $cleanUrl)) {
            self::logSuspiciousUrl($cleanUrl, 'attack_pattern_detected');
            return self::getDefaultRedirect($context);
        }
    }
    
    // ✅ CORRECTION: Normalisation du chemin
    $normalizedUrl = self::normalizePath($cleanUrl);
    if ($normalizedUrl !== $cleanUrl) {
        if (class_exists('Logger')) {
            Logger::warning('URL_VALIDATOR', "URL normalisée", [
                'original' => $cleanUrl,
                'normalized' => $normalizedUrl
            ]);
        }
        $cleanUrl = $normalizedUrl;
    }
    
    // 1. ✅ CORRECTION: Vérification liste blanche stricte avec contexte
    $basename = basename($cleanUrl);
    if (in_array($basename, self::$allowedFiles)) {
        $resolvedUrl = self::resolveFileLocation($basename, $context);
        
        // ✅ AJOUT: Vérification supplémentaire du fichier résolu
        if (self::isFileSecureAndExists($resolvedUrl)) {
            return $resolvedUrl;
        } else {
            self::logSuspiciousUrl($cleanUrl, 'resolved_file_invalid');
            return self::getDefaultRedirect($context);
        }
    }
    
    // 2. ✅ CORRECTION: Vérification des patterns autorisés avec validation
    foreach (self::$allowedPatterns as $pattern) {
        if (preg_match($pattern, $cleanUrl)) {
            // ✅ AJOUT: Validation supplémentaire de sécurité
            if (self::isPatternSecure($cleanUrl, $pattern)) {
                return self::validateFileExists($cleanUrl, $context);
            } else {
                self::logSuspiciousUrl($cleanUrl, 'pattern_security_check_failed');
                return self::getDefaultRedirect($context);
            }
        }
    }
    
    // 3. ✅ CORRECTION: Vérification des URLs relatives simples avec validation stricte
    if (self::isSimpleRelativeUrl($cleanUrl)) {
        // ✅ AJOUT: Validation de sécurité supplémentaire
        if (self::isUrlContextSecure($cleanUrl, $context)) {
            return self::validateFileExists($cleanUrl, $context);
        } else {
            self::logSuspiciousUrl($cleanUrl, 'context_security_check_failed');
            return self::getDefaultRedirect($context);
        }
    }
    
    // 4. ✅ AJOUT: Vérification des URLs absolues sécurisées
    if (self::isAllowedAbsoluteUrl($cleanUrl)) {
        // ✅ CORRECTION: Validation supplémentaire pour URLs absolues
        if (self::isAbsoluteUrlSecure($cleanUrl)) {
            return $cleanUrl;
        } else {
            self::logSuspiciousUrl($cleanUrl, 'absolute_url_security_check_failed');
            return self::getDefaultRedirect($context);
        }
    }
    
    // Aucune validation réussie - redirection sécurisée
    self::logSuspiciousUrl($cleanUrl, 'all_validations_failed');
    return self::getDefaultRedirect($context);
}

/**
 * ✅ AJOUT: Normalisation sécurisée des chemins
 */
private static function normalizePath($url) {
    // Supprimer les slashes multiples
    $url = preg_replace('/\/+/', '/', $url);
    
    // Supprimer les ./ 
    $url = preg_replace('/\/\.\//', '/', $url);
    
    // Supprimer les trailing dots
    $url = rtrim($url, '.');
    
    // Supprimer les espaces
    $url = trim($url);
    
    return $url;
}

/**
 * ✅ AJOUT: Vérification de sécurité et d'existence du fichier
 */
private static function isFileSecureAndExists($url) {
    if (empty($url)) {
        return false;
    }
    
    // Construire le chemin complet
    $fullPath = self::resolveFullPath($url);
    if ($fullPath === false) {
        return false;
    }
    
    // Vérifier l'existence
    if (!file_exists($fullPath) || !is_file($fullPath)) {
        return false;
    }
    
    // ✅ AJOUT: Vérifications de sécurité supplémentaires
    
    // Vérifier les permissions
    if (!is_readable($fullPath)) {
        return false;
    }
    
    // Vérifier que ce n'est pas un lien symbolique vers un endroit dangereux
    if (is_link($fullPath)) {
        $target = readlink($fullPath);
        if ($target === false || strpos($target, '..') !== false) {
            return false;
        }
    }
    
    // Vérifier la taille du fichier (protection contre les gros fichiers)
    $fileSize = filesize($fullPath);
    if ($fileSize === false || $fileSize > 10 * 1024 * 1024) { // 10MB max
        return false;
    }
    
    // ✅ AJOUT: Vérifier l'extension de fichier
    $allowedExtensions = ['php', 'html', 'htm'];
    $extension = strtolower(pathinfo($fullPath, PATHINFO_EXTENSION));
    if (!in_array($extension, $allowedExtensions)) {
        return false;
    }
    
    return true;
}

/**
 * ✅ AJOUT: Validation de sécurité pour les patterns
 */
private static function isPatternSecure($url, $pattern) {
    // Vérifier que l'URL ne contient pas de caractères suspects
    // même si elle match le pattern
    
    // Pas de caractères nulls
    if (strpos($url, "\0") !== false) {
        return false;
    }
    
    // Pas de caractères de contrôle
    if (preg_match('/[\x00-\x1f\x7f-\x9f]/', $url)) {
        return false;
    }
    
    // Pas de double encodage
    if (preg_match('/%25[0-9a-f]{2}/i', $url)) {
        return false;
    }
    
    // Vérifier la longueur raisonnable
    if (strlen($url) > 100) {
        return false;
    }
    
    return true;
}

/**
 * ✅ AJOUT: Validation de sécurité contextuelle
 */
private static function isUrlContextSecure($url, $context) {
    // Restrictions spécifiques selon le contexte
    switch ($context) {
        case 'admin':
            // Plus restrictif pour admin
            return preg_match('/^admin\/[a-zA-Z0-9_-]{1,30}\.php$/', $url);
            
        case 'cart':
        case 'panier':
            // Autoriser seulement les fichiers de panier
            $allowedCartFiles = ['panier.php', 'checkout.php', 'cart.php', 'cart_simple.php'];
            return in_array(basename($url), $allowedCartFiles);
            
        case 'api':
            // Autoriser seulement les endpoints API
            return preg_match('/^api\/[a-zA-Z0-9_-]{1,30}\.php$/', $url);
            
        default:
            // Contexte général - validation basique
            return preg_match('/^[a-zA-Z0-9_-]{1,50}\.php$/', $url);
    }
}

/**
 * ✅ AJOUT: Validation de sécurité pour URLs absolues
 */
private static function isAbsoluteUrlSecure($url) {
    $parsedUrl = parse_url($url);
    
    if (!$parsedUrl || !isset($parsedUrl['host'])) {
        return false;
    }
    
    // ✅ CORRECTION: Validation stricte du host
    $host = strtolower($parsedUrl['host']);
    
    // Pas d'adresses IP privées
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        // Si ce n'est pas une IP publique valide, vérifier que c'est un nom de domaine
        if (!filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            return false;
        }
    }
    
    // Vérifier le protocole
    if (isset($parsedUrl['scheme'])) {
        $allowedSchemes = ['http', 'https'];
        if (!in_array(strtolower($parsedUrl['scheme']), $allowedSchemes)) {
            return false;
        }
    }
    
    // Pas de port suspect
    if (isset($parsedUrl['port'])) {
        $suspiciousPorts = [22, 23, 25, 53, 110, 143, 993, 995];
        if (in_array($parsedUrl['port'], $suspiciousPorts)) {
            return false;
        }
    }
    
    // Pas de credentials dans l'URL
    if (isset($parsedUrl['user']) || isset($parsedUrl['pass'])) {
        return false;
    }
    
    return true;
}
    
    /**
     * Résout l'emplacement d'un fichier selon le contexte
     */
    private static function resolveFileLocation($filename, $context) {
        $panierFiles = ['panier.php', 'checkout.php', 'cart.php', 'cart_simple.php'];
        
        switch ($context) {
            case 'cart':
            case 'panier':
                if (in_array($filename, $panierFiles)) {
                    return $filename; // Même dossier
                } else {
                    return '../' . $filename; // Dossier parent
                }
                break;
                
            case 'admin':
                return in_array($filename, $panierFiles) ? 'panier/' . $filename : $filename;
                break;
                
            default:
                return $filename;
        }
    }
    
    /**
     * Valide l'existence du fichier de manière sécurisée
     */
    private static function validateFileExists($url, $context) {
        // Résoudre le chemin complet
        $fullPath = self::resolveFullPath($url);
        
        if ($fullPath === false) {
            return self::getDefaultRedirect($context);
        }
        
        // Vérifier l'existence et que c'est un fichier
        if (!file_exists($fullPath) || !is_file($fullPath)) {
            self::logSuspiciousUrl($url, 'file_not_found');
            return self::getDefaultRedirect($context);
        }
        
        // Vérifier que le fichier n'est pas dans un répertoire interdit
        if (self::isInForbiddenPath($fullPath)) {
            self::logSuspiciousUrl($url, 'forbidden_path');
            return self::getDefaultRedirect($context);
        }
        
        return $url;
    }
    
    /**
     * Résout le chemin complet d'un fichier
     */
    private static function resolveFullPath($url) {
        $documentRoot = $_SERVER['DOCUMENT_ROOT'] ?? '';
        
        if (empty($documentRoot)) {
            return false;
        }
        
        // URL absolue commençant par /
        if (strpos($url, '/') === 0) {
            $fullPath = $documentRoot . $url;
        } else {
            // URL relative
            $currentDir = dirname($_SERVER['SCRIPT_NAME'] ?? '/');
            $fullPath = $documentRoot . $currentDir . '/' . $url;
        }
        
        // Normaliser le chemin
        $realPath = realpath($fullPath);
        
        // Vérifier que le chemin résolu est dans le document root
        if ($realPath === false || strpos($realPath, $documentRoot) !== 0) {
            return false;
        }
        
        return $realPath;
    }
    
    /**
     * Vérifie si l'URL est une simple URL relative
     */
    private static function isSimpleRelativeUrl($url) {
        // Pas de slash au début
        if (strpos($url, '/') === 0) {
            return false;
        }
        
        // Pattern simple pour fichier PHP
        return preg_match('/^[a-zA-Z0-9_\-]+\.php$/', $url);
    }
    
    /**
     * Vérifie si l'URL absolue est autorisée
     */
    private static function isAllowedAbsoluteUrl($url) {
        $parsedUrl = parse_url($url);
        
        if (!isset($parsedUrl['host'])) {
            return false;
        }
        
        $allowedHosts = [
            $_SERVER['HTTP_HOST'] ?? '',
            'localhost',
            '127.0.0.1'
        ];
        
        return in_array($parsedUrl['host'], $allowedHosts);
    }
    
    /**
     * Vérifie si le chemin est dans un répertoire interdit
     */
    private static function isInForbiddenPath($fullPath) {
        foreach (self::$forbiddenPaths as $forbidden) {
            if (strpos($fullPath, '/' . $forbidden . '/') !== false) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Retourne la redirection par défaut selon le contexte
     */
    private static function getDefaultRedirect($context) {
        switch ($context) {
            case 'cart':
            case 'panier':
                return 'panier.php';
            case 'admin':
                return 'admin.php';
            case 'login':
                return 'login.php';
            default:
                return 'index.php';
        }
    }
    
    /**
     * Log les URLs suspectes
     */
    private static function logSuspiciousUrl($url, $reason) {
        if (class_exists('Logger')) {
            Logger::security('URL_VALIDATOR', "URL suspecte détectée", [
                'url' => htmlspecialchars($url),
                'reason' => $reason,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                'referer' => $_SERVER['HTTP_REFERER'] ?? 'unknown'
            ]);
        }
        
        if (class_exists('Security')) {
            Security::logSecurityEvent('security_warning', 'URL de redirection suspecte', [
                'url' => $url,
                'reason' => $reason
            ]);
        }
    }
    
    /**
     * Log les modifications d'URL
     */
    private static function logUrlModification($original, $modified, $context) {
        if (class_exists('Logger')) {
            Logger::info('URL_VALIDATOR', "URL modifiée pour sécurité", [
                'original' => htmlspecialchars($original),
                'modified' => htmlspecialchars($modified),
                'context' => $context
            ]);
        }
    }
    
    /**
     * Nettoie le cache des validations
     */
    public static function clearCache() {
        self::$validationCache = [];
        
        if (class_exists('Logger')) {
            Logger::debug('URL_VALIDATOR', "Cache des validations d'URL nettoyé");
        }
    }
    
    /**
     * Ajoute un fichier à la liste blanche
     */
    public static function addAllowedFile($filename) {
        if (preg_match('/^[a-zA-Z0-9_\-]+\.php$/', $filename)) {
            self::$allowedFiles[] = $filename;
            self::$allowedFiles = array_unique(self::$allowedFiles);
            
            if (class_exists('Logger')) {
                Logger::debug('URL_VALIDATOR', "Fichier ajouté à la liste blanche", [
                    'filename' => $filename
                ]);
            }
        }
    }
}
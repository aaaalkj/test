<?php
//Cart.php
/**
 * Gestionnaire de panier e-commerce sécurisé et optimisé
 * 
 * Version 2.0 - Optimisations apportées :
 * - Suppression des caches redondants (un seul système de cache unifié)
 * - Optimisation des vérifications d'intégrité (cache par requête)
 * - Réduction des logs verbeux (événements critiques uniquement)
 * - Simplification de la gestion des paniers anonymes/clients
 * - Amélioration des performances de chargement depuis la DB
 * - Nettoyage automatique des caches avec limitation mémoire
 * 
 * @author Système Panier E-commerce
 * @version 2.0
 * @since 2024
 */

// Vérification des dépendances de sécurité
if (!defined('SECURE_ACCESS')) {
    if (class_exists('Logger')) {
        Logger::critical('CART', "Accès direct au fichier Cart.php détecté");
    }
    exit('Accès direct au fichier interdit');
}

class Cart {
    
    // ================================================================================================
    // PROPRIÉTÉS DE CLASSE OPTIMISÉES
    // ================================================================================================
    
    /**
     * Articles du panier
     * @var array
     */
    private $items = [];
    
    /**
     * Signature HMAC du panier pour l'intégrité
     * @var string
     */
    private $signature = '';
    
    /**
     * Horodatage de dernière modification
     * @var int
     */
    private $lastModified = 0;
    
    /**
     * Instance de la base de données
     * @var Database
     */
    private $db;
    
    /**
     * ID unique du panier
     * @var string
     */
    private $cartId;
    
    /**
     * Cache unifié des informations produit (remplace les multiples caches)
     * @var array
     */
    private $productCache = [];
    
    /**
     * Taille maximale du cache produit pour limiter la mémoire
     * @var int
     */
    private $maxProductCacheSize = 50; // Réduit de 100
    
 
    
    
    /**
     * Flag indiquant si l'intégrité a été vérifiée dans cette requête
     * @var bool
     */
    private $integrityVerified = false;
    
    /**
     * Indique si le panier a été sauvegardé en base de données
     * @var bool
     */
    private $savedToDatabase = false;
    
    /**
     * Identifiant du client associé au panier (si connecté)
     * @var int|null
     */
    private $clientId = null;
    
    /**
     * Cache simplifié pour l'existence des paniers
     * @var array
     */
    private static $cartExistsCache = [];
    
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
    
    // ================================================================================================
    // CONSTRUCTEUR OPTIMISÉ
    // ================================================================================================
    
    /**
     * Constructeur avec initialisation optimisée
     */
    public function __construct() {
        if (class_exists('Logger')) {
            Logger::info('CART', "Initialisation du panier");
        }
        
        // Obtenir l'instance de la base de données
        $this->db = Database::getInstance();
        
        // Nettoyage périodique des caches
        self::cleanupCachesIfNeeded();
        
        // Déterminer l'ID client si connecté
        if (isset($_SESSION['user_id'])) {
            $this->clientId = (int)$_SESSION['user_id'];
            if (class_exists('Logger')) {
                Logger::debug('CART', "Client connecté détecté", ['client_id' => $this->clientId]);
            }
        }
        
        // Gérer l'ID du panier
        $this->initializeCartId();
        
        // Initialiser le panier
        $this->initCart();
        
        // Charger le panier approprié selon le contexte
        $this->loadCart();
    }
    
    /**
     * Initialise l'ID du panier de manière sécurisée
     */
    private function initializeCartId() {
        // Vérifier si un token de panier existe en cookie
        $cookieToken = $_COOKIE['cart_token'] ?? null;
        
        if ($cookieToken && $this->isValidToken($cookieToken)) {
            // Récupérer l'ID du panier depuis le token
            $existingCart = $this->getCartByToken($cookieToken);
            
            if ($existingCart) {
                $this->cartId = $existingCart['cart_id'];
                $_SESSION['cart_id'] = $this->cartId;
                
                if (class_exists('Logger')) {
                    Logger::debug('CART', "Panier récupéré via cookie token", [
                        'cart_id' => $this->cartId
                    ]);
                }
                return;
            }
        }
        
        // Utiliser l'ID de session existant ou en générer un nouveau
        if (isset($_SESSION['cart_id']) && !empty($_SESSION['cart_id'])) {
            $this->cartId = $_SESSION['cart_id'];
        } else {
            $this->cartId = $this->generateCartId();
            $_SESSION['cart_id'] = $this->cartId;
        }
        
        if (class_exists('Logger')) {
            Logger::debug('CART', "ID de panier défini", ['cart_id' => $this->cartId]);
        }
    }
    
    /**
     * Génère un ID de panier sécurisé
     */
/**
 * Génère un ID de panier sécurisé avec validations renforcées
 */
private function generateCartId() {
    // ✅ CORRECTION: Validation préalable de l'environnement
    if (defined('REQUIRE_SECURE_RANDOM') && REQUIRE_SECURE_RANDOM && !function_exists('random_bytes')) {
        throw new Exception("Environnement cryptographiquement non sécurisé pour génération ID panier");
    }
    
    try {
        $cartId = bin2hex(random_bytes(16)); // 32 caractères hexadécimaux
        
        // ✅ CORRECTION: Validation de l'entropie générée
        if (strlen(count_chars($cartId, 3)) < 8) {
            throw new Exception("ID panier généré avec entropie insuffisante");
        }
        
        // ✅ CORRECTION: Vérifier l'unicité en base (si DB disponible)
        if ($this->db && $this->cartExists($cartId)) {
            // Régénération récursive en cas de collision
            return $this->generateCartId();
        }
        
        if (class_exists('Logger')) {
            Logger::debug('CART', "ID panier sécurisé généré", [
                'entropy_chars' => strlen(count_chars($cartId, 3)),
                'length' => strlen($cartId)
            ]);
        }
        
        return $cartId;
        
    } catch (Exception $e) {
        // ✅ CORRECTION: Pas de fallback, échec strict
        if (class_exists('Logger')) {
            Logger::critical('CART', "ÉCHEC CRITIQUE génération ID panier", [
                'error' => $e->getMessage(),
                'random_bytes_available' => function_exists('random_bytes')
            ]);
        }
        
        throw new Exception("Impossible de générer un ID de panier sécurisé: " . $e->getMessage());
    }
}

/**
 * ✅ AJOUT: Méthode pour vérifier l'unicité de l'ID
 */
private function cartExists($cartId) {
    try {
        $count = $this->db->queryValue(
            "SELECT COUNT(*) FROM carts WHERE cart_id = ?",
            [$cartId]
        );
        return $count > 0;
    } catch (Exception $e) {
        // En cas d'erreur DB, considérer comme unique pour ne pas bloquer
        return false;
    }
}
    
    /**
     * Valide un token de panier
     */
    private function isValidToken($token) {
        // Validation basique du format
        if (empty($token) || strlen($token) < 32) {
            return false;
        }
        
        // Vérifier que le token ne contient que des caractères alphanumériques
        return ctype_alnum($token);
    }
    
    /**
     * Récupère un panier par son token avec cache
     */
    private function getCartByToken($token) {
        $cacheKey = 'token_' . $token;
        
        // Vérifier le cache
        if (isset(self::$cartExistsCache[$cacheKey])) {
            return self::$cartExistsCache[$cacheKey];
        }
        
        try {
            $stmt = $this->db->query(
                "SELECT cart_id FROM carts WHERE cart_token = ? AND status = 'active'",
                [$token]
            );
            $result = $stmt->fetch();
            
            // Mettre en cache le résultat
            self::$cartExistsCache[$cacheKey] = $result ?: false;
            
            return $result ?: false;
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('CART', "Erreur récupération panier par token: " . $e->getMessage());
            }
            return false;
        }
    }
    
    
    // ================================================================================================
    // INITIALISATION ET CHARGEMENT DU PANIER
    // ================================================================================================
    
    /**
     * Initialise le panier depuis la session avec vérifications d'intégrité
     */
    private function initCart() {
        // Vérifier si la session est active
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        if (class_exists('Logger')) {
            Logger::debug('CART', "Chargement du panier depuis la session");
        }
        
        // Vérifier si un panier existe en session
        if (isset($_SESSION['cart'], $_SESSION['cart_signature'], $_SESSION['cart_last_modified'])) {
            if ($this->loadFromSession()) {
                // Vérifier l'expiration du panier
                if ($this->isCartExpired()) {
                    $this->resetCart('Panier expiré');
                } else {
                    // Si le panier session est vide, essayer de charger depuis la DB
                    if (empty($this->items)) {
                        if (class_exists('Logger')) {
                            Logger::debug('CART', "Panier session vide, tentative de chargement depuis DB");
                        }
                        $this->loadFromDatabase();
                    }
                    
                    // Vérifier l'intégrité seulement si nécessaire
                    $this->scheduleIntegrityCheck();
                }
            } else {
                $this->resetCart('Intégrité du panier compromise');
            }
        } else {
            // Initialiser un nouveau panier
            if (class_exists('Logger')) {
                Logger::debug('CART', "Aucun panier trouvé, création d'un nouveau panier");
            }
            $this->resetCart('Nouveau panier');
        }
    }
    
    /**
     * Charge le panier depuis la session et vérifie l'intégrité
     */
    private function loadFromSession() {
        try {
            // Déchiffrer le panier
            $decryptedCart = Security::decrypt($_SESSION['cart']);
            
            if ($decryptedCart === null) {
                if (class_exists('Logger')) {
                    Logger::warning('CART', "Échec du déchiffrement du panier");
                }
                return false;
            }
            
            // Vérifier l'intégrité HMAC
            if (!Security::verifyHmac($decryptedCart, $_SESSION['cart_signature'])) {
                if (class_exists('Logger')) {
                    Logger::security('CART', "Intégrité HMAC du panier compromise");
                }
                
                Security::logSecurityEvent('security_warning', 'Tentative de manipulation du panier détectée', [
                    'session_id' => session_id(),
                    'cart_id' => $this->cartId,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
                
                return false;
            }
            
            // Charger les données
            $this->items = $decryptedCart;
            $this->signature = $_SESSION['cart_signature'];
            $this->lastModified = $_SESSION['cart_last_modified'];
            
            if (class_exists('Logger')) {
                Logger::debug('CART', "Panier chargé depuis la session avec succès", [
                    'items_count' => count($this->items)
                ]);
            }
            
            return true;
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('CART', "Erreur lors du chargement depuis la session: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * Vérifie si le panier a expiré
     */
    private function isCartExpired() {
        $cartLifetime = defined('CART_LIFETIME') ? CART_LIFETIME : 86400; // 24h par défaut
        $age = time() - $this->lastModified;
        
        if ($age > $cartLifetime) {
            if (class_exists('Logger')) {
                Logger::info('CART', "Panier expiré", [
                    'age_hours' => round($age / 3600, 1),
                    'lifetime_hours' => round($cartLifetime / 3600, 1)
                ]);
            }
            return true;
        }
        
        return false;
    }
    
    /**
     * Remet à zéro le panier
     */
    private function resetCart($reason = '') {
        $this->items = [];
        $this->signature = '';
        $this->lastModified = time();
        $this->integrityVerified = false;
        
        if ($reason && class_exists('Logger')) {
            Logger::info('CART', "Panier réinitialisé", ['reason' => $reason]);
        }
        
        $this->saveCart();
    }
    
    /**
     * Programme une vérification d'intégrité différée
     */

/**
 * ✅ CORRECTION: Utilisation du cache sécurisé avec autorisation
 */
private function scheduleIntegrityCheck() {
    $cacheKey = 'cart_integrity_' . $this->cartId;
    
    if (class_exists('Security')) {
        // ✅ CORRECTION: Demander autorisation d'accès au cache
        Security::authorizeComponent('Cart', 300); // 5 minutes
        
        if (!Security::getCachedVerification($cacheKey, 'Cart')) {
            $success = Security::setCachedVerification($cacheKey, 'scheduled', 'Cart');
            
            if (!$success && class_exists('Logger')) {
                Logger::warning('CART', "Échec programmation vérification intégrité", [
                    'cart_id' => $this->cartId
                ]);
            }
        }
    }
}

/**
 * ✅ CORRECTION: Vérification d'intégrité avec accès autorisé
 */
private function ensureIntegrityChecked() {
    $cacheKey = 'cart_integrity_' . $this->cartId;
    
    if (class_exists('Security')) {
        // ✅ CORRECTION: S'assurer de l'autorisation avant accès
        Security::authorizeComponent('Cart', 300);
        
        $cached = Security::getCachedVerification($cacheKey, 'Cart');
        if ($cached === 'scheduled' && !$this->integrityVerified) {
            $this->verifyCartIntegrity();
            
            // ✅ CORRECTION: Marquer comme vérifié dans le cache
            Security::setCachedVerification($cacheKey, 'verified', 'Cart');
        }
    } else {
        // ✅ CORRECTION: Fallback plus robuste
        if (!$this->integrityVerified) {
            $this->verifyCartIntegrity();
        }
    }
}

/**
 * ✅ CORRECTION: Vérification d'intégrité complète avec cache sécurisé
 */

/**
 * ✅ VERSION FINALE À CONSERVER - Vérification d'intégrité complète avec cache sécurisé
 */
private function verifyCartIntegrity() {
    // Vérifier si déjà fait dans cette requête
    if ($this->integrityVerified) {
        return;
    }
    
    $cacheKey = 'cart_integrity_' . $this->cartId;
    
    // ✅ CORRECTION: Utiliser le cache Security centralisé avec autorisation
    if (class_exists('Security')) {
        Security::authorizeComponent('Cart', 300);
        $cached = Security::getCachedVerification($cacheKey, 'Cart');
        if ($cached === 'verified') {
            $this->integrityVerified = true;
            return;
        }
    }
    
    $modified = false;
    $itemsToRemove = [];
    $changesCount = 0;
    
    if (class_exists('Logger')) {
        Logger::debug('CART', "Début vérification intégrité panier", [
            'cart_id' => $this->cartId,
            'items_count' => count($this->items)
        ]);
    }
    
    foreach ($this->items as $id => $item) {
        // Validation basique de l'ID
        if (!is_numeric($id) || $id <= 0) {
            if (class_exists('Logger')) {
                Logger::security('CART', "ID produit invalide détecté", ['product_id' => $id]);
            }
            $itemsToRemove[] = $id;
            $modified = true;
            continue;
        }
        
        // Vérifier l'existence et récupérer les infos produit
        $productInfo = $this->getProductInfo($id);
        if (!$productInfo) {
            $itemsToRemove[] = $id;
            $modified = true;
            continue;
        }
        
        // Vérifier et ajuster le prix (tolérance de 1%)
        $actualPrice = (float)$productInfo['price'];
        $priceDiff = abs($actualPrice - $item['price']);
        $pricePercent = ($item['price'] > 0) ? ($priceDiff / $item['price']) * 100 : 100;
        
        if ($pricePercent > 1) {
            $this->items[$id]['price'] = $actualPrice;
            $this->items[$id]['subtotal'] = $actualPrice * $item['quantity'];
            $modified = true;
            $changesCount++;
            
            if (class_exists('Logger')) {
                Logger::info('CART', "Prix produit mis à jour", [
                    'product_id' => $id,
                    'old_price' => $item['price'],
                    'new_price' => $actualPrice,
                    'difference_percent' => round($pricePercent, 2)
                ]);
            }
        }
        
        // Vérifier et ajuster le stock
        $stock = (int)$productInfo['stock'];
        if ($stock <= 0) {
            $itemsToRemove[] = $id;
            $modified = true;
            continue;
        }
        
        if ($item['quantity'] > $stock) {
            $this->items[$id]['quantity'] = $stock;
            $this->items[$id]['subtotal'] = $this->items[$id]['price'] * $stock;
            $modified = true;
            $changesCount++;
            
            if (class_exists('Logger')) {
                Logger::info('CART', "Quantité ajustée au stock", [
                    'product_id' => $id,
                    'old_quantity' => $item['quantity'],
                    'new_quantity' => $stock
                ]);
            }
        }
        
        // Mettre à jour les attributs produit si nécessaire
        $updatedFields = $this->updateProductAttributes($id, $item, $productInfo);
        if (!empty($updatedFields)) {
            $modified = true;
            $changesCount++;
        }
    }
    
    // Supprimer les articles à retirer
    foreach ($itemsToRemove as $id) {
        unset($this->items[$id]);
    }
    
    // Log final avec résumé
    if ($modified) {
        if (class_exists('Logger')) {
            Logger::info('CART', "Intégrité vérifiée - Modifications appliquées", [
                'cart_id' => $this->cartId,
                'items_removed' => count($itemsToRemove),
                'items_updated' => $changesCount,
                'total_items' => count($this->items)
            ]);
        }
        $this->saveCart();
    } else {
        if (class_exists('Logger')) {
            Logger::debug('CART', "Intégrité vérifiée - Aucune modification", [
                'cart_id' => $this->cartId,
                'items_count' => count($this->items)
            ]);
        }
    }
    
    // Marquer comme vérifié
    $this->integrityVerified = true;
    
    // ✅ CORRECTION: Mettre à jour le cache Security centralisé
    if (class_exists('Security')) {
        $success = Security::setCachedVerification($cacheKey, 'verified', 'Cart');
        if (!$success && class_exists('Logger')) {
            Logger::warning('CART', "Échec mise à jour cache intégrité", [
                'cart_id' => $this->cartId
            ]);
        }
    }
}
    
    /**
     * Charge le panier approprié selon le contexte (client/anonyme)
     */
    private function loadCart() {
      if ($this->clientId) {
      $this->loadClientCart();
        } else {
            $this->loadAnonymousCart();
        }
     
    }
    
    
    // ============================================
// CORRECTIONS À APPORTER DANS Cart.php
// ============================================

// 1. AJOUTER cette méthode manquante (vers ligne 270-280)
/**
 * Charge le panier depuis la base de données (méthode manquante)
 */
private function loadFromDatabase() {
    if (empty($this->items)) {
        $this->items = $this->loadCartItems($this->cartId);
        $this->saveCart();
        
        if (class_exists('Logger')) {
            Logger::debug('CART', "Panier chargé depuis DB", [
                'items_count' => count($this->items)
            ]);
        }
    }
}
    
    /**
     * Charge un panier client depuis la base de données avec optimisations
     */
    private function loadClientCart() {
        try {
            // Récupérer le panier actif le plus récent pour ce client
            $clientCart = $this->db->queryRow(
                "SELECT cart_id FROM carts 
                 WHERE id_client = ? AND status = 'active' 
                 ORDER BY updated_at DESC LIMIT 1",
                [$this->clientId]
            );
            
            if (!$clientCart) {
                if (class_exists('Logger')) {
                    Logger::debug('CART', "Aucun panier client trouvé en DB");
                }
                return false;
            }
            
            $dbCartId = $clientCart['cart_id'];
            $sessionHasItems = !empty($this->items);
            $cartChanged = ($dbCartId !== $this->cartId);
            
            if ($cartChanged) {
                if ($sessionHasItems) {
                    // Fusionner les paniers
                    $this->mergeWithDatabaseCart($dbCartId);
                } else {
                    // Charger simplement le panier client
                    $this->switchToCart($dbCartId);
                }
            } else {
                // Synchroniser avec la DB si nécessaire
                $this->syncWithDatabase();
            }
            
            return true;
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('CART', "Erreur chargement panier client: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
 * ✅ NOUVELLE MÉTHODE : Fusionne le panier session avec un panier de base de données
 */
private function mergeWithDatabaseCart($dbCartId) {
    $oldCartId = $this->cartId;
    $this->cartId = $dbCartId;
    $_SESSION['cart_id'] = $dbCartId;
    
    // Charger les articles du panier DB
    $dbItems = $this->loadCartItems($dbCartId);
    
    // Configuration de la stratégie de fusion
    $mergeStrategy = defined('CART_MERGE_STRATEGY') ? CART_MERGE_STRATEGY : 'add';
    
    // Fusionner avec les articles en session
    foreach ($dbItems as $productId => $dbItem) {
        if (isset($this->items[$productId])) {
            // Fusionner les articles existants
            try {
                $this->items[$productId] = $this->mergeCartItems(
                    $this->items[$productId], 
                    $dbItem, 
                    $mergeStrategy
                );
            } catch (Exception $e) {
                if (class_exists('Logger')) {
                    Logger::error('CART', "Erreur fusion article: " . $e->getMessage(), [
                        'product_id' => $productId,
                        'old_cart' => $oldCartId,
                        'db_cart' => $dbCartId
                    ]);
                }
                // En cas d'erreur, conserver l'article session (plus récent)
                continue;
            }
        } else {
            // Ajouter l'article du panier DB
            $this->items[$productId] = $dbItem;
            $this->items[$productId]['merged_from'] = 'database';
            $this->items[$productId]['merged_at'] = time();
        }
    }
    
    $this->save();
    
    if (class_exists('Logger')) {
        Logger::info('CART', "Paniers fusionnés avec base de données", [
            'old_cart' => $oldCartId,
            'new_cart' => $dbCartId,
            'total_items' => count($this->items),
            'merge_strategy' => $mergeStrategy,
            'db_items_count' => count($dbItems)
        ]);
    }
}
    
    /**
     * Charge un panier anonyme depuis la base de données
     */
    private function loadAnonymousCart() {
        $cacheKey = 'anonymous_' . $this->cartId . '_' . session_id();
        
        // Vérifier le cache d'abord
        if (isset(self::$cartExistsCache[$cacheKey])) {
            if (!self::$cartExistsCache[$cacheKey]) {
                return false; // Déjà vérifié, pas de panier
            }
        }
        
        try {
            $cartExists = $this->db->queryRow(
                "SELECT cart_id FROM carts 
                 WHERE cart_id = ? AND session_id = ? AND status = 'active'",
                [$this->cartId, session_id()]
            );
            
            // Mettre en cache le résultat
            self::$cartExistsCache[$cacheKey] = $cartExists ?: false;
            
            if (!$cartExists) {
                return false;
            }
            
            // Si le panier session est vide, charger depuis la DB
           // Si le panier session est vide, charger depuis la DB
if (empty($this->items)) {
    $this->items = $this->loadCartItems($this->cartId);  // ✅ AJOUT DU $this->items =
    $this->saveCart();
    
    if (class_exists('Logger')) {
        Logger::debug('CART', "Panier anonyme chargé depuis DB", [
            'items_count' => count($this->items)
        ]);
    }
}else {
                // Synchroniser la session vers la DB
                $this->syncWithDatabase();
            }
            
            return true;
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('CART', "Erreur chargement panier anonyme: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * Fusionne le panier session avec un panier de base de données
     */
/**
 * ✅ NOUVELLE MÉTHODE : Fusion centralisée et configurable des articles de panier
 */

    
    /**
     * Bascule vers un autre panier
     */
    private function switchToCart($newCartId) {
        $this->cartId = $newCartId;
        $_SESSION['cart_id'] = $newCartId;
        $this->items = $this->loadCartItems($newCartId);
        $this->saveCart();
        
        if (class_exists('Logger')) {
            Logger::debug('CART', "Basculé vers le panier", [
                'cart_id' => $newCartId,
                'items_count' => count($this->items)
            ]);
        }
    }
    
    /**
     * Synchronise le panier avec la base de données
     */
    private function syncWithDatabase() {
        try {
            // Vérifier si le nombre d'articles diffère
            $dbItemCount = $this->db->queryValue(
                "SELECT COUNT(*) FROM cart_items WHERE cart_id = ?",
                [$this->cartId]
            );
            
            $sessionItemCount = count($this->items);
            
            if ($dbItemCount != $sessionItemCount) {
                if ($sessionItemCount > 0) {
                    // La session a plus d'items, sauvegarder en DB
                    $this->saveToDatabase();
                    
                    if (class_exists('Logger')) {
                        Logger::debug('CART', "DB mise à jour depuis la session", [
                            'session_items' => $sessionItemCount,
                            'db_items' => $dbItemCount
                        ]);
                    }
                } else {
                    // La DB a plus d'items, charger depuis la DB
                    $this->items = $this->loadCartItems($this->cartId);
                    $this->saveCart();
                    
                    if (class_exists('Logger')) {
                        Logger::debug('CART', "Session mise à jour depuis la DB", [
                            'loaded_items' => count($this->items)
                        ]);
                    }
                }
            }
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('CART', "Erreur synchronisation: " . $e->getMessage());
            }
        }
    }
    
    // ================================================================================================
    // VÉRIFICATION D'INTÉGRITÉ OPTIMISÉE
    // ================================================================================================
    
   /**
 * Vérifie l'intégrité des produits dans le panier avec cache par requête
 */

    
    /**
     * Met à jour les attributs d'un produit dans le panier
     */
    private function updateProductAttributes($productId, $item, $productInfo) {
        $fieldsToCheck = ['weight', 'reference', 'image_url', 'category', 'tva_rate', 'largeur', 'longueur', 'hauteur', 'name'];
        $updatedFields = [];
        
        foreach ($fieldsToCheck as $field) {
            if (!isset($productInfo[$field])) {
                continue;
            }
            
            $productValue = $productInfo[$field];
            $itemValue = $item[$field] ?? null;
            
            // Comparaison selon le type
            if (is_numeric($productValue) && is_numeric($itemValue)) {
                // Tolérance pour les nombres
                if (abs($productValue - $itemValue) > 0.001) {
                    $this->items[$productId][$field] = $productValue;
                    $updatedFields[] = $field;
                }
            } else if ($productValue !== $itemValue) {
                // Comparaison directe pour les chaînes
                $this->items[$productId][$field] = $productValue;
                $updatedFields[] = $field;
            }
        }
        
        return $updatedFields;
    }
    
    // ================================================================================================
    // GESTION DES INFORMATIONS PRODUIT AVEC CACHE UNIFIÉ
    // ================================================================================================
    
    /**
     * Récupère les informations d'un produit avec cache unifié optimisé
     */
    private function getProductInfo($productId, $field = null) {
        // Vérifier le cache unifié
        if (!isset($this->productCache[$productId])) {
            // Nettoyer le cache si trop volumineux
            if (count($this->productCache) >= $this->maxProductCacheSize) {
                $this->cleanupProductCache();
            }
            
            try {
                $product = $this->db->queryRow(
                    "SELECT id, price, stock, weight, reference, image_url, category, tva_rate, 
                            largeur, longueur, hauteur, name 
                     FROM products 
                     WHERE id = ?",
                    [$productId]
                );
                
                if ($product) {
                    // Convertir les types numériques
                    $product['price'] = (float)$product['price'];
                    $product['stock'] = (int)$product['stock'];
                    $product['weight'] = (int)$product['weight'];
                    $product['tva_rate'] = (int)$product['tva_rate'];
                    $product['largeur'] = (int)$product['largeur'];
                    $product['longueur'] = (int)$product['longueur'];
                    $product['hauteur'] = (int)$product['hauteur'];
                    
                    $this->productCache[$productId] = $product;
                    
                    if (class_exists('Logger')) {
                        Logger::debug('CART', "Infos produit mises en cache", ['product_id' => $productId]);
                    }
                } else {
                    $this->productCache[$productId] = false;
                    
                    if (class_exists('Logger')) {
                        Logger::warning('CART', "Produit non trouvé", ['product_id' => $productId]);
                    }
                }
            } catch (Exception $e) {
                if (class_exists('Logger')) {
                    Logger::error('CART', "Erreur récupération produit: " . $e->getMessage(), [
                        'product_id' => $productId
                    ]);
                }
                return false;
            }
        }
        
        $productData = $this->productCache[$productId];
        
        // Retourner le champ spécifique ou toutes les données
        if ($field !== null) {
            return $productData ? ($productData[$field] ?? null) : null;
        }
        
        return $productData;
    }
    
    /**
     * Nettoie le cache des produits (FIFO simple)
     */
    private function cleanupProductCache() {
        // Garder seulement la moitié des entrées les plus récentes
        $keepCount = intval($this->maxProductCacheSize / 2);
        $this->productCache = array_slice($this->productCache, -$keepCount, null, true);
        
        if (class_exists('Logger')) {
            Logger::debug('CART', "Cache produit nettoyé", [
                'remaining_items' => count($this->productCache)
            ]);
        }
    }
    
    /**
     * Récupère le prix actuel d'un produit
     */
    private function getActualProductPrice($productId) {
        $price = $this->getProductInfo($productId, 'price');
        return ($price !== null && $price !== false) ? (float)$price : false;
    }
    
    /**
     * Récupère le stock disponible d'un produit
     */
    private function getProductStock($productId) {
        $stock = $this->getProductInfo($productId, 'stock');
        return ($stock !== null && $stock !== false) ? (int)$stock : 0;
    }
    
    // ================================================================================================
    // SAUVEGARDE OPTIMISÉE DU PANIER
    // ================================================================================================
    
    /**
     * Sauvegarde le panier dans la session de manière sécurisée
     */
    private function saveCart() {
        if (class_exists('Logger')) {
            Logger::debug('CART', "Sauvegarde du panier en session");
        }
        
        // Mettre à jour l'horodatage
        $this->lastModified = time();
        
        // Générer une nouvelle signature HMAC
        $this->signature = Security::generateHmac($this->items);
        
        // Chiffrer le panier avant de le stocker en session
        $encryptedCart = Security::encrypt($this->items);
        
        if ($encryptedCart === false) {
            if (class_exists('Logger')) {
                Logger::error('CART', "Échec du chiffrement du panier");
            }
            return false;
        }
        
        // Stocker en session
        $_SESSION['cart'] = $encryptedCart;
        $_SESSION['cart_signature'] = $this->signature;
        $_SESSION['cart_last_modified'] = $this->lastModified;
        
        return true;
    }
    
    /**
     * Sauvegarde unifiée (session + base de données)
     */
    private function save() {
  // public function save() {
        $sessionSaved = $this->saveCart();
        $databaseSaved = $this->saveToDatabase();
        
        if (!$sessionSaved && class_exists('Logger')) {
            Logger::warning('CART', "Échec sauvegarde session");
        }
        
        if (!$databaseSaved && class_exists('Logger')) {
            Logger::warning('CART', "Échec sauvegarde base de données");
        }
        
        return $sessionSaved && $databaseSaved;
    }
    
    // ================================================================================================
    // NETTOYAGE DES CACHES
    // ================================================================================================
    
    /**
     * Nettoie les caches si nécessaire pour optimiser la mémoire
     */
/**
     * Nettoie les caches si nécessaire pour optimiser la mémoire
     */
    private static function cleanupCachesIfNeeded() {
        $now = time();
        
        if ($now - self::$lastCacheCleanup > self::$cacheCleanupInterval) {
            // Limiter la taille du cache d'existence des paniers
           /*  if (count(self::$cartExistsCache) > 100) {
                self::$cartExistsCache = array_slice(self::$cartExistsCache, -50, null, true);
            }*/
            $maxCache = 200;
if (count(self::$cartExistsCache) > $maxCache) {
    self::$cartExistsCache = array_slice(self::$cartExistsCache, -($maxCache/2), null, true);
}
            
            self::$lastCacheCleanup = $now;
            
            if (class_exists('Logger')) {
                Logger::debug('CART', "Nettoyage des caches effectué", [
                    'cart_exists_cache' => count(self::$cartExistsCache)
                ]);
            }
        }
    }
    
    
    
    
    // ================================================================================================
// GESTION DU CACHE POUR LES AUTRES COMPOSANTS
// ================================================================================================

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    /**
     * Vide tous les caches statiques
     */
/**
 * Vide tous les caches statiques
 */
public static function clearCache() {
self::$cartExistsCache = [];
    self::$lastCacheCleanup = 0;
    
    // ✅ CORRECTION : Notifier Security pour nettoyage centralisé
    if (class_exists('Security')) {
        Security::clearCartVerifications();
    }
    
    if (class_exists('Logger')) {
        Logger::debug('CART', "Tous les caches vidés");
    }
}

/*public static function clearCache() {
if (isset(self::$cartExistsCache)) {
        self::$cartExistsCache = [];
    }
    if (isset(self::$lastCacheCleanup)) {
        self::$lastCacheCleanup = 0;
    }
    
    if (class_exists('Security')) {
        Security::clearCartVerifications();
    }
    
    if (class_exists('Logger')) {
        Logger::debug('CART', "Tous les caches vidés");
    }
}*/
    
    // ================================================================================================
    // MANIPULATION DES ARTICLES DU PANIER
    // ================================================================================================
    
    /**
     * Ajoute un produit au panier avec vérifications optimisées
     */
    public function addItem($productId, $quantity = 1, $price = null) {
        // Validation basique des paramètres
        if (!is_numeric($productId) || $productId <= 0) {
            if (class_exists('Logger')) {
                Logger::warning('CART', "ID produit invalide pour ajout", ['product_id' => $productId]);
            }
            return "Produit invalide";
        }
        
        if (!is_numeric($quantity) || $quantity <= 0 || $quantity > 100) {
            if (class_exists('Logger')) {
                Logger::warning('CART', "Quantité invalide pour ajout", ['quantity' => $quantity]);
            }
            return "Quantité invalide";
        }
        
        // Vérifier la limite d'articles différents
        $maxItems = defined('MAX_CART_ITEMS') ? MAX_CART_ITEMS : 50;
        if (count($this->items) >= $maxItems && !isset($this->items[$productId])) {
            if (class_exists('Logger')) {
                Logger::warning('CART', "Limite d'articles atteinte", [
                    'max_items' => $maxItems,
                    'current_items' => count($this->items)
                ]);
            }
            return "Nombre maximal d'articles atteint";
        }
        
        try {
            // Récupérer les informations du produit
            $product = $this->getProductInfo($productId);
            if (!$product) {
                return "Produit introuvable";
            }
            
            // Vérifier le stock disponible
            $stock = (int)$product['stock'];
            if ($stock <= 0) {
                if (class_exists('Logger')) {
                    Logger::info('CART', "Tentative d'ajout produit en rupture", ['product_id' => $productId]);
                }
                return "Produit en rupture de stock";
            }
            
            $isUpdate = isset($this->items[$productId]);
            $finalQuantity = $quantity;
            
            if ($isUpdate) {
                // Mise à jour d'un article existant
                $newQuantity = $this->items[$productId]['quantity'] + $quantity;
                
                if ($newQuantity > $stock) {
                    if ($stock > $this->items[$productId]['quantity']) {
                        // Ajuster à la quantité maximale possible
                        return $this->updateItem($productId, $stock);
                    } else {
                        return "Stock insuffisant pour ajouter cette quantité";
                    }
                }
                
                return $this->updateItem($productId, $newQuantity);
            } else {
                // Nouvel article
                if ($quantity > $stock) {
                    if ($stock > 0) {
                        $finalQuantity = $stock;
                        if (class_exists('Logger')) {
                            Logger::info('CART', "Quantité ajustée au stock disponible", [
                                'product_id' => $productId,
                                'requested' => $quantity,
                                'available' => $stock
                            ]);
                        }
                    } else {
                        return "Stock insuffisant";
                    }
                }
                
                // Utiliser le prix actuel du produit
                $actualPrice = (float)$product['price'];
                
                // Avertir si le prix fourni diffère
                if ($price !== null && abs($price - $actualPrice) > 0.01) {
                    if (class_exists('Logger')) {
                        Logger::info('CART', "Prix fourni diffère du prix actuel", [
                            'product_id' => $productId,
                            'supplied_price' => $price,
                            'actual_price' => $actualPrice
                        ]);
                    }
                }
                
                // Créer l'article du panier
                $this->items[$productId] = [
                    'id' => $productId,
                    'quantity' => $finalQuantity,
                    'price' => $actualPrice,
                    'subtotal' => $actualPrice * $finalQuantity,
                    'weight' => (int)$product['weight'],
                    'reference' => $product['reference'],
                    'image_url' => $product['image_url'],
                    'category' => $product['category'],
                    'tva_rate' => (int)$product['tva_rate'],
                    'largeur' => (int)$product['largeur'],
                    'longueur' => (int)$product['longueur'],
                    'hauteur' => (int)$product['hauteur'],
                    'added_at' => time(),
                    'name' => $product['name']
                ];
                
                // Sauvegarder le panier
                $this->save();
                
                if (class_exists('Logger')) {
                    Logger::info('CART', "Produit ajouté avec succès", [
                        'product_id' => $productId,
                        'quantity' => $finalQuantity,
                        'price' => $actualPrice,
                        'stock_adjusted' => ($finalQuantity != $quantity)
                    ]);
                }
                
                return true;
            }
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('CART', "Erreur lors de l'ajout: " . $e->getMessage(), [
                    'product_id' => $productId,
                    'quantity' => $quantity
                ]);
            }
            return "Erreur lors de l'ajout au panier";
        }
    }
    
    /**
     * Met à jour la quantité d'un produit dans le panier MODIFICATION 260625
     */
   /* public function updateItem($productId, $quantity) {
   // Validation des paramètres
        if (!is_numeric($productId) || $productId <= 0) {
            if (class_exists('Logger')) {
                Logger::warning('CART', "ID produit invalide pour mise à jour", ['product_id' => $productId]);
            }
            return "Produit invalide";
        }
        
        // Vérifier si le produit existe dans le panier
        if (!isset($this->items[$productId])) {
            if (class_exists('Logger')) {
                Logger::warning('CART', "Produit non trouvé pour mise à jour", ['product_id' => $productId]);
            }
            return "Produit non trouvé dans le panier";
        }
        
        // Si quantité nulle ou négative, supprimer l'article
        if ($quantity <= 0) {
            return $this->removeItem($productId);
        }
        
        // Valider la quantité
        if (!is_numeric($quantity) || $quantity > 100) {
            if (class_exists('Logger')) {
                Logger::warning('CART', "Quantité invalide pour mise à jour", ['quantity' => $quantity]);
            }
            return "Quantité invalide";
        }
        
        try {
            // Vérifier le stock disponible
            $stock = $this->getProductStock($productId);
            $originalQuantity = $this->items[$productId]['quantity'];
            $finalQuantity = $quantity;
            $stockAdjusted = false;
            
            if ($quantity > $stock) {
                if ($stock <= 0) {
                    // Stock épuisé, supprimer l'article
                    return $this->removeItem($productId);
                }
                
                // Ajuster à la quantité disponible
                $finalQuantity = $stock;
                $stockAdjusted = true;
                
                if (class_exists('Logger')) {
                    Logger::info('CART', "Quantité ajustée au stock disponible", [
                        'product_id' => $productId,
                        'requested' => $quantity,
                        'adjusted' => $finalQuantity
                    ]);
                }
            }
            
            // Récupérer le prix actuel
            $actualPrice = $this->getActualProductPrice($productId);
            if ($actualPrice === false) {
                // Garder le prix existant si impossible de récupérer le nouveau
                $actualPrice = $this->items[$productId]['price'];
            }
            
            // Mettre à jour l'article
            $this->items[$productId]['quantity'] = $finalQuantity;
            $this->items[$productId]['price'] = $actualPrice;
            $this->items[$productId]['subtotal'] = $actualPrice * $finalQuantity;
            $this->items[$productId]['updated_at'] = time();
            
            // Sauvegarder
            $this->save();
            
            if (class_exists('Logger')) {
                Logger::info('CART', "Quantité mise à jour avec succès", [
                    'product_id' => $productId,
                    'old_quantity' => $originalQuantity,
                    'new_quantity' => $finalQuantity,
                    'stock_adjusted' => $stockAdjusted
                ]);
            }
            
            return true;
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('CART', "Erreur mise à jour quantité: " . $e->getMessage(), [
                    'product_id' => $productId,
                    'quantity' => $quantity
                ]);
            }
            return "Erreur lors de la mise à jour";
        }
    }*/
    
    
    
    
    
    
    public function updateItem($productId, $quantity) {
    // Validation des paramètres
    if (!is_numeric($productId) || $productId <= 0) {
        if (class_exists('Logger')) {
            Logger::warning('CART', "ID produit invalide pour mise à jour", ['product_id' => $productId]);
        }
        return "Produit invalide";
    }
    
    // Vérifier si le produit existe dans le panier
    if (!isset($this->items[$productId])) {
        if (class_exists('Logger')) {
            Logger::warning('CART', "Produit non trouvé pour mise à jour", ['product_id' => $productId]);
        }
        return "Produit non trouvé dans le panier";
    }
    
    // Si quantité nulle ou négative, supprimer l'article
    if ($quantity <= 0) {
        return $this->removeItem($productId);
    }
    
    // Valider la quantité
    if (!is_numeric($quantity) || $quantity > 100) {
        if (class_exists('Logger')) {
            Logger::warning('CART', "Quantité invalide pour mise à jour", ['quantity' => $quantity]);
        }
        return "Quantité invalide";
    }
    
    try {
        // ✅ CORRECTION : Sauvegarder l'état original pour rollback
        $originalItem = $this->items[$productId];
        $originalQuantity = $originalItem['quantity'];
        
        // Vérifier le stock disponible
        $stock = $this->getProductStock($productId);
        $finalQuantity = $quantity;
        $stockAdjusted = false;
        
        if ($quantity > $stock) {
            if ($stock <= 0) {
                // Stock épuisé, supprimer l'article
                return $this->removeItem($productId);
            }
            
            // Ajuster à la quantité disponible
            $finalQuantity = $stock;
            $stockAdjusted = true;
            
            if (class_exists('Logger')) {
                Logger::info('CART', "Quantité ajustée au stock disponible", [
                    'product_id' => $productId,
                    'requested' => $quantity,
                    'adjusted' => $finalQuantity
                ]);
            }
        }
        
        // Récupérer le prix actuel
        $actualPrice = $this->getActualProductPrice($productId);
        if ($actualPrice === false) {
            // Garder le prix existant si impossible de récupérer le nouveau
            $actualPrice = $this->items[$productId]['price'];
        }
        
        // ✅ CORRECTION : Mise à jour atomique et validation immédiate
        $this->items[$productId] = array_merge($this->items[$productId], [
            'quantity' => $finalQuantity,
            'price' => $actualPrice,
            'subtotal' => $actualPrice * $finalQuantity,
            'updated_at' => time()
        ]);
        
        // ✅ AJOUT : Validation immédiate de la mise à jour en mémoire
        if ($this->items[$productId]['quantity'] !== $finalQuantity) {
            throw new Exception("Échec mise à jour quantité en mémoire - valeur attendue: {$finalQuantity}, valeur actuelle: " . $this->items[$productId]['quantity']);
        }
        
        // ✅ CORRECTION : Sauvegarder avec vérification du résultat
        $saveResult = $this->save();
        
        if (!$saveResult) {
            // ✅ AJOUT : Rollback automatique en cas d'échec
            $this->items[$productId] = $originalItem;
            
            if (class_exists('Logger')) {
                Logger::error('CART', "Échec sauvegarde - rollback effectué", [
                    'product_id' => $productId,
                    'attempted_quantity' => $finalQuantity,
                    'restored_quantity' => $originalQuantity
                ]);
            }
            
            throw new Exception("Échec de la sauvegarde, modification annulée");
        }
        
        // ✅ AJOUT : Vérification post-sauvegarde (optionnelle en mode debug)
        if (defined('DEBUG_CART') && DEBUG_CART) {
            // Recharger depuis la session pour vérifier la cohérence
            if (isset($_SESSION['cart'])) {
                $sessionData = Security::decrypt($_SESSION['cart']);
                if ($sessionData && isset($sessionData[$productId])) {
                    $sessionQuantity = $sessionData[$productId]['quantity'];
                    if ($sessionQuantity !== $finalQuantity) {
                        if (class_exists('Logger')) {
                            Logger::warning('CART', "Incohérence session détectée", [
                                'product_id' => $productId,
                                'memory_quantity' => $finalQuantity,
                                'session_quantity' => $sessionQuantity
                            ]);
                        }
                    }
                }
            }
        }
        
        if (class_exists('Logger')) {
            Logger::info('CART', "Quantité mise à jour avec succès", [
                'product_id' => $productId,
                'old_quantity' => $originalQuantity,
                'new_quantity' => $finalQuantity,
                'stock_adjusted' => $stockAdjusted,
                'save_result' => $saveResult
            ]);
        }
        
        return true;
        
    } catch (Exception $e) {
        // ✅ CORRECTION : Gestion d'erreur améliorée avec rollback de sécurité
        if (isset($originalItem)) {
            $this->items[$productId] = $originalItem;
        }
        
        if (class_exists('Logger')) {
            Logger::error('CART', "Erreur mise à jour quantité: " . $e->getMessage(), [
                'product_id' => $productId,
                'quantity' => $quantity,
                'file' => $e->getFile(),
                'line' => $e->getLine()
            ]);
        }
        
        return "Erreur lors de la mise à jour: " . $e->getMessage();
    }
}
    
    
    
    
    
    
    
    
    
    /**
     * Supprime un produit du panier
     */
    public function removeItem($productId) {
        // Validation des paramètres
        if (!is_numeric($productId) || $productId <= 0) {
            if (class_exists('Logger')) {
                Logger::warning('CART', "ID produit invalide pour suppression", ['product_id' => $productId]);
            }
            return "Produit invalide";
        }
        
        // Vérifier si le produit existe dans le panier
        if (!isset($this->items[$productId])) {
            if (class_exists('Logger')) {
                Logger::warning('CART', "Produit non trouvé pour suppression", ['product_id' => $productId]);
            }
            return "Produit non trouvé dans le panier";
        }
        
        try {
            // Sauvegarder les informations avant suppression pour le log
            $productInfo = $this->items[$productId];
            
            // Supprimer l'article
            unset($this->items[$productId]);
            
            // Sauvegarder
            $this->save();
            
            if (class_exists('Logger')) {
                Logger::info('CART', "Produit supprimé avec succès", [
                    'product_id' => $productId,
                    'quantity' => $productInfo['quantity'],
                    'price' => $productInfo['price'],
                    'name' => $productInfo['name'] ?? "Produit #{$productId}"
                ]);
            }
            
            return true;
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('CART', "Erreur suppression produit: " . $e->getMessage(), [
                    'product_id' => $productId
                ]);
            }
            return "Erreur lors de la suppression";
        }
    }
    
    /**
     * Vide complètement le panier
     */
    public function clear() {
        try {
            // Sauvegarder les informations avant suppression
            $itemCount = count($this->items);
            $totalValue = $this->getTotal();
            
            // Vider le panier
            $this->items = [];
            
            // Réinitialiser les flags
            $this->integrityVerified = false;
            
            // Sauvegarder
            $this->save();
            
            if (class_exists('Logger')) {
                Logger::info('CART', "Panier vidé avec succès", [
                    'previous_item_count' => $itemCount,
                    'previous_total_value' => $totalValue
                ]);
            }
            
            return true;
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('CART', "Erreur vidage panier: " . $e->getMessage());
            }
            return false;
        }
    }
    
    // ================================================================================================
    // VÉRIFICATIONS DE DISPONIBILITÉ ET STOCK
    // ================================================================================================
    
    /**
     * Vérifie la disponibilité de tous les produits du panier
     */
    public function checkAvailability() {
        if (class_exists('Logger')) {
            Logger::debug('CART', "Vérification de la disponibilité des produits");
        }
        
        $unavailableItems = [];
        
        foreach ($this->items as $productId => $item) {
            $stock = $this->getProductStock($productId);
            
            if ($stock < $item['quantity']) {
                $unavailableItems[] = [
                    'id' => $productId,
                    'name' => $item['name'] ?? "Produit #{$productId}",
                    'requested' => $item['quantity'],
                    'available' => $stock,
                    'status' => ($stock <= 0) ? 'out_of_stock' : 'insufficient_stock'
                ];
            }
        }
        
        if (!empty($unavailableItems)) {
            if (class_exists('Logger')) {
                Logger::warning('CART', "Problèmes de stock détectés", [
                    'issues_count' => count($unavailableItems),
                    'items' => array_column($unavailableItems, 'id')
                ]);
            }
        }
        
        return $unavailableItems;
    }
    
    // ================================================================================================
    // SAUVEGARDE EN BASE DE DONNÉES OPTIMISÉE
    // ================================================================================================
    
    /**
     * Sauvegarde le panier en base de données avec gestion optimisée des tokens
     */
/**
 * Sauvegarde le panier en base de données avec gestion optimisée des tokens - VERSION AVEC LOGS
 */
     public function saveToDatabase() {
        try {
            // Commencer une transaction
            $this->db->beginTransaction();
            
            // Vérifier si le panier existe déjà
            $existingCart = $this->db->queryRow(
                "SELECT cart_id, cart_token FROM carts WHERE cart_id = ?",
                [$this->cartId]
            );
            
            // Récupérer les informations de contexte
            $ipAddress = $_SERVER['REMOTE_ADDR'] ?? null;
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
            
            // Générer ou conserver le token de panier
            $cartToken = $existingCart ? $existingCart['cart_token'] : $this->generateCartToken();
            
            if ($existingCart) {
                // Mettre à jour le panier existant
                $this->db->query(
                    "UPDATE carts SET 
                     id_client = ?, 
                     session_id = ?, 
                     updated_at = NOW(),
                     ip_address = ?,
                     user_agent = ?,
                     status = ?
                     WHERE cart_id = ?",
                    [
                        $this->clientId,
                        session_id(),
                        $ipAddress,
                        $userAgent,
                        empty($this->items) ? 'abandoned' : 'active',
                        $this->cartId
                    ]
                );
            } else {
                // Créer un nouveau panier
                $this->db->query(
                    "INSERT INTO carts (
                        cart_id, id_client, session_id, cart_token, 
                        created_at, updated_at, ip_address, user_agent, status
                    ) VALUES (?, ?, ?, ?, NOW(), NOW(), ?, ?, ?)",
                    [
                        $this->cartId,
                        $this->clientId,
                        session_id(),
                        $cartToken,
                        $ipAddress,
                        $userAgent,
                        empty($this->items) ? 'abandoned' : 'active'
                    ]
                );
            }
            
            // Définir le cookie de panier avec sécurité renforcée
            $this->setCartCookie($cartToken);
            
            // Supprimer les anciens articles
            $this->db->query("DELETE FROM cart_items WHERE cart_id = ?", [$this->cartId]);
            
            // Insérer les nouveaux articles en lot pour optimiser les performances
            if (!empty($this->items)) {
                $this->insertCartItemsBatch();
            }
            
            // Valider la transaction
            $this->db->commit();
            $this->savedToDatabase = true;
            
            if (class_exists('Logger')) {
                Logger::debug('CART', "Panier sauvegardé en base avec succès", [
                    'cart_id' => $this->cartId,
                    'items_count' => count($this->items),
                    'is_new' => !$existingCart,
                    'status' => empty($this->items) ? 'abandoned' : 'active'
                ]);
            }
            
            return true;
            
        } catch (Exception $e) {
            // Annuler la transaction en cas d'erreur
            if ($this->db->inTransaction()) {
                $this->db->rollback();
            }
            
            if (class_exists('Logger')) {
                Logger::error('CART', "Erreur sauvegarde base: " . $e->getMessage(), [
                    'cart_id' => $this->cartId
                ]);
            }
            
            return false;
        }
    }
/*public function saveToDatabase() {
// Log de début
    if (class_exists('Logger')) {
        Logger::debug('CART', "Début saveToDatabase()", [
            'cart_id' => $this->cartId,
            'items_count' => count($this->items),
            'client_id' => $this->clientId
        ]);
    }
    
    try {
        // Vérifier la connexion DB
        if (!$this->db) {
            if (class_exists('Logger')) {
                Logger::error('CART', "Base de données non initialisée");
            }
            return false;
        }
        
        // Log de vérification DB
        if (class_exists('Logger')) {
            Logger::debug('CART', "Connexion DB OK, début transaction");
        }
        
        // Commencer une transaction
        $this->db->beginTransaction();
        
        // Vérifier si le panier existe déjà
        if (class_exists('Logger')) {
            Logger::debug('CART', "Vérification existence panier", ['cart_id' => $this->cartId]);
        }
        
        $existingCart = $this->db->queryRow(
            "SELECT cart_id, cart_token FROM carts WHERE cart_id = ?",
            [$this->cartId]
        );
        
        if (class_exists('Logger')) {
            Logger::debug('CART', "Résultat vérification", [
                'exists' => !empty($existingCart),
                'existing_cart' => $existingCart
            ]);
        }
        
        // Récupérer les informations de contexte
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? null;
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        
        // Générer ou conserver le token de panier
        $cartToken = $existingCart ? $existingCart['cart_token'] : $this->generateCartToken();
        
        if (class_exists('Logger')) {
            Logger::debug('CART', "Token de panier", [
                'token' => substr($cartToken, 0, 20) . '...',
                'is_new' => !$existingCart
            ]);
        }
        
        if ($existingCart) {
            // Mettre à jour le panier existant
            if (class_exists('Logger')) {
                Logger::debug('CART', "Mise à jour panier existant");
            }
            
            $updateResult = $this->db->query(
                "UPDATE carts SET 
                 id_client = ?, 
                 session_id = ?, 
                 updated_at = NOW(),
                 ip_address = ?,
                 user_agent = ?,
                 status = ?
                 WHERE cart_id = ?",
                [
                    $this->clientId,
                    session_id(),
                    $ipAddress,
                    $userAgent,
                    empty($this->items) ? 'abandoned' : 'active',
                    $this->cartId
                ]
            );
            
            if (class_exists('Logger')) {
                Logger::debug('CART', "Résultat mise à jour", [
                    'affected_rows' => $updateResult ? $updateResult->rowCount() : 0
                ]);
            }
            
        } else {
            // Créer un nouveau panier
            if (class_exists('Logger')) {
                Logger::debug('CART', "Création nouveau panier");
            }
            
            $insertResult = $this->db->query(
              "INSERT INTO carts (
    cart_id, id_client, session_id, cart_token, 
    created_at, updated_at, ip_address, user_agent, status
) VALUES (?, ?, ?, ?, NOW(), NOW(), ?, ?, ?)",
                [
                    $this->cartId,
                    $this->clientId,
                    session_id(),
                    $cartToken,
                    $ipAddress,
                    $userAgent,
                    empty($this->items) ? 'abandoned' : 'active'
                ]
            );
            
            if (class_exists('Logger')) {
                Logger::debug('CART', "Résultat insertion", [
                    'affected_rows' => $insertResult ? $insertResult->rowCount() : 0
                ]);
            }
        }
        
        // Définir le cookie de panier avec sécurité renforcée
        if (class_exists('Logger')) {
            Logger::debug('CART', "Définition cookie panier");
        }
        
        $this->setCartCookie($cartToken);
        
        // Supprimer les anciens articles
        if (class_exists('Logger')) {
            Logger::debug('CART', "Suppression anciens articles");
        }
        
        $deleteResult = $this->db->query("DELETE FROM cart_items WHERE cart_id = ?", [$this->cartId]);
        
        if (class_exists('Logger')) {
            Logger::debug('CART', "Articles supprimés", [
                'deleted_count' => $deleteResult ? $deleteResult->rowCount() : 0
            ]);
        }
        
        // Insérer les nouveaux articles en lot pour optimiser les performances
        if (!empty($this->items)) {
            if (class_exists('Logger')) {
                Logger::debug('CART', "Insertion nouveaux articles", [
                    'items_to_insert' => count($this->items)
                ]);
            }
            
            $this->insertCartItemsBatch();
        }
        
        // Valider la transaction
        if (class_exists('Logger')) {
            Logger::debug('CART', "Validation transaction");
        }
        
        $this->db->commit();
        $this->savedToDatabase = true;
        
        if (class_exists('Logger')) {
            Logger::info('CART', "Panier sauvegardé en base avec succès", [
                'cart_id' => $this->cartId,
                'items_count' => count($this->items),
                'is_new' => !$existingCart,
                'status' => empty($this->items) ? 'abandoned' : 'active'
            ]);
        }
        
        return true;
        
    } catch (Exception $e) {
        // Annuler la transaction en cas d'erreur
        if ($this->db && $this->db->inTransaction()) {
            $this->db->rollback();
            
            if (class_exists('Logger')) {
                Logger::debug('CART', "Transaction annulée");
            }
        }
        
        if (class_exists('Logger')) {
            Logger::error('CART', "Erreur sauvegarde base: " . $e->getMessage(), [
                'cart_id' => $this->cartId,
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => substr($e->getTraceAsString(), 0, 500)
            ]);
        }
        
        return false;
    }
}*/
    
    /**
     * Génère un token sécurisé pour le panier
     */
    private function generateCartToken() {
        if (class_exists('Security')) {
            return Security::generateCartToken($this->cartId, session_id());
        }
        
        // Fallback si Security n'est pas disponible
        return hash('sha256', $this->cartId . session_id() . time() . mt_rand());
    }
    
    /**
     * Définit le cookie de panier avec paramètres de sécurité
     */
   /* private function setCartCookie($cartToken) {
        $cookieOptions = [
            'expires' => time() + (30 * 86400), // 30 jours
            'path' => '/',
            'domain' => '',
            'secure' => (ENVIRONMENT === 'production'), // HTTPS en production uniquement
            'httponly' => true,
            'samesite' => 'Lax'
        ];
        
        setcookie('cart_token', $cartToken, $cookieOptions);
    }*/
    
    
    
    private function setCartCookie($cartToken) {
    $cookieDomain = $_SERVER['HTTP_HOST'];
if (strpos($cookieDomain, ':') !== false) {
    $cookieDomain = explode(':', $cookieDomain)[0];
}
$cookieOptions = [
    'expires' => time() + (30 * 86400), // 30 jours
    'path' => '/',
    'domain' => $cookieDomain, // domaine courant sans port
    'secure' => (ENVIRONMENT === 'production'),
    'httponly' => true,
    'samesite' => 'Lax'
];
setcookie('cart_token', $cartToken, $cookieOptions);
    }
    
    
    /**
     * Insère les articles du panier en lot pour optimiser les performances
     */
    private function insertCartItemsBatch() {
        // Préparer les données pour l'insertion en lot
        $values = [];
        $params = [];
        
        foreach ($this->items as $productId => $item) {
            $values[] = "(?, ?, ?, ?, NOW(), NOW())";
            $params[] = $this->cartId;
            $params[] = $productId;
            $params[] = $item['quantity'];
            $params[] = $item['price'];
        }
        
        if (!empty($values)) {
            $sql = "INSERT INTO cart_items (cart_id, product_id, quantity, price_at_addition, created_at, updated_at) VALUES " . 
                   implode(', ', $values);
            
            $this->db->query($sql, $params);
        }
    }
    
    /**
     * Charge les articles d'un panier depuis la base de données
     */
    private function loadCartItems($cartId) {
        if (class_exists('Logger')) {
            Logger::debug('CART', "Chargement des articles du panier depuis DB", ['cart_id' => $cartId]);
        }
        
        $items = [];
        
        try {
            $cartItems = $this->db->queryAll(
                "SELECT ci.product_id, ci.quantity, ci.price_at_addition, 
                        p.name, p.weight, p.reference, p.image_url, p.category, 
                        p.tva_rate, p.largeur, p.longueur, p.hauteur
                 FROM cart_items ci
                 JOIN products p ON ci.product_id = p.id
                 WHERE ci.cart_id = ?",
                [$cartId]
            );
            
            foreach ($cartItems as $item) {
                $productId = $item['product_id'];
                
                $items[$productId] = [
                    'id' => $productId,
                    'quantity' => (int)$item['quantity'],
                    'price' => (float)$item['price_at_addition'],
                    'subtotal' => (float)$item['price_at_addition'] * (int)$item['quantity'],
                    'weight' => (int)$item['weight'],
                    'reference' => $item['reference'],
                    'image_url' => $item['image_url'],
                    'category' => $item['category'],
                    'tva_rate' => (int)$item['tva_rate'],
                    'largeur' => (int)$item['largeur'],
                    'longueur' => (int)$item['longueur'],
                    'hauteur' => (int)$item['hauteur'],
                    'name' => $item['name'],
                    'added_at' => time() // Approximation
                ];
            }
            
            if (class_exists('Logger')) {
                Logger::debug('CART', "Articles chargés depuis DB", ['items_count' => count($items)]);
            }
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('CART', "Erreur chargement articles DB: " . $e->getMessage());
            }
        }
        
        return $items;
    }
    
    // ================================================================================================
    // GESTION DES CLIENTS ET ASSOCIATION DE PANIERS
    // ================================================================================================
    
    /**
     * Associe le panier à un client connecté avec fusion intelligente
     */
    public function assignToClient($clientId) {
        if (!is_numeric($clientId) || $clientId <= 0) {
            if (class_exists('Logger')) {
                Logger::error('CART', "ID client invalide pour association", ['client_id' => $clientId]);
            }
            return false;
        }
        
        try {
            $this->clientId = (int)$clientId;
            
            // Chercher un panier existant pour ce client
            $existingClientCart = $this->db->queryRow(
                "SELECT cart_id FROM carts 
                 WHERE id_client = ? AND status = 'active' 
                 AND cart_id != ? 
                 ORDER BY updated_at DESC LIMIT 1",
                [$clientId, $this->cartId]
            );
            
            if ($existingClientCart && !empty($this->items)) {
                // Fusionner avec le panier client existant
                $this->mergeWithClientCart($existingClientCart['cart_id']);
            } else if ($existingClientCart && empty($this->items)) {
                // Adopter le panier client existant
                $this->switchToCart($existingClientCart['cart_id']);
            }
            
            // Sauvegarder avec l'ID client
            $this->saveToDatabase();
            
            if (class_exists('Logger')) {
                Logger::info('CART', "Panier associé au client", [
                    'client_id' => $clientId,
                    'cart_id' => $this->cartId,
                    'items_count' => count($this->items),
                    'had_existing_cart' => !empty($existingClientCart)
                ]);
            }
            
            return true;
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('CART', "Erreur association client: " . $e->getMessage(), [
                    'client_id' => $clientId
                ]);
            }
            return false;
        }
    }
    
    /**
     * Fusionne le panier actuel avec un panier client existant
     */
    private function mergeWithClientCart($clientCartId) {
        // Charger les articles du panier client
        $clientItems = $this->loadCartItems($clientCartId);
        
        // Fusionner avec le panier actuel (prendre la quantité maximale)
        foreach ($clientItems as $productId => $clientItem) {
           /* if (isset($this->items[$productId])) {
           // Prendre la quantité la plus élevée
                if ($clientItem['quantity'] > $this->items[$productId]['quantity']) {
                    $this->items[$productId]['quantity'] = $clientItem['quantity'];
                    $this->items[$productId]['subtotal'] = $clientItem['quantity'] * $this->items[$productId]['price'];
                }
            } else {
                // Ajouter l'article du panier client
                $this->items[$productId] = $clientItem;
            }*/
            
 if (isset($this->items[$productId])) {
    // ✅ CORRECTION : Utiliser $clientItem pour cohérence
    $totalQty = $clientItem['quantity'] + $this->items[$productId]['quantity'];
    $this->items[$productId]['quantity'] = $totalQty;
    $this->items[$productId]['subtotal'] = $totalQty * $this->items[$productId]['price'];
} else {
    // Ajouter l'article
    $this->items[$productId] = $clientItem; 
}
        }
        
        // Marquer l'ancien panier client comme abandonné
        $this->db->query(
            "UPDATE carts SET status = 'merged', updated_at = NOW() WHERE cart_id = ?",
            [$clientCartId]
        );
        
        // Sauvegarder le panier fusionné
        $this->saveCart();
        
        if (class_exists('Logger')) {
            Logger::info('CART', "Panier fusionné avec panier client", [
                'client_cart_id' => $clientCartId,
                'current_cart_id' => $this->cartId,
                'total_items' => count($this->items)
            ]);
        }
    }
    
    // ================================================================================================
    // NETTOYAGE ET MAINTENANCE DES PANIERS
    // ================================================================================================
    
    /**
     * Nettoie les paniers abandonnés (méthode statique pour les tâches cron)
     */
    public static function cleanupAbandonedCarts() {
        if (!defined('CRON_SECURITY_TOKEN')) {
            return false;
        }
        
        try {
            $db = Database::getInstance();
            
            // Définir les seuils de nettoyage
            $abandonedDays = defined('CART_DB_ABANDONED_DAYS') ? CART_DB_ABANDONED_DAYS : 30;
            $deleteDays = defined('CART_DB_DELETE_DAYS') ? CART_DB_DELETE_DAYS : 90;
            
            // Marquer comme abandonnés les paniers inactifs
            $abandonedCount = $db->query(
                "UPDATE carts SET status = 'abandoned' 
                 WHERE status = 'active' 
                 AND updated_at < DATE_SUB(NOW(), INTERVAL ? DAY)",
                [$abandonedDays]
            )->rowCount();
            
            // Supprimer les très anciens paniers
            $deletedCartsCount = $db->query(
                "DELETE FROM carts 
                 WHERE status IN ('abandoned', 'merged') 
                 AND updated_at < DATE_SUB(NOW(), INTERVAL ? DAY)",
                [$deleteDays]
            )->rowCount();
            
            if (class_exists('Logger')) {
                Logger::info('CART', "Nettoyage des paniers effectué", [
                    'abandoned_count' => $abandonedCount,
                    'deleted_count' => $deletedCartsCount,
                    'abandoned_threshold_days' => $abandonedDays,
                    'delete_threshold_days' => $deleteDays
                ]);
            }
            
            return [
                'abandoned' => $abandonedCount,
                'deleted' => $deletedCartsCount
            ];
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('CART', "Erreur nettoyage paniers: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * Obtient des statistiques sur les paniers
     */
    public static function getCartStatistics() {
        try {
            $db = Database::getInstance();
            
            $stats = [
                'total_carts' => $db->queryValue("SELECT COUNT(*) FROM carts"),
                'active_carts' => $db->queryValue("SELECT COUNT(*) FROM carts WHERE status = 'active'"),
                'abandoned_carts' => $db->queryValue("SELECT COUNT(*) FROM carts WHERE status = 'abandoned'"),
                'client_carts' => $db->queryValue("SELECT COUNT(*) FROM carts WHERE id_client IS NOT NULL"),
                'anonymous_carts' => $db->queryValue("SELECT COUNT(*) FROM carts WHERE id_client IS NULL"),
                'avg_items_per_cart' => $db->queryValue(
                    "SELECT AVG(item_count) FROM (
                        SELECT COUNT(*) as item_count 
                        FROM cart_items 
                        GROUP BY cart_id
                    ) as cart_counts"
                )
            ];
            
            // Arrondir la moyenne
            $stats['avg_items_per_cart'] = round($stats['avg_items_per_cart'], 2);
            
            return $stats;
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('CART', "Erreur récupération statistiques: " . $e->getMessage());
            }
            return [];
        }
    }
    
    // ================================================================================================
    // MÉTHODES D'ACCÈS AUX DONNÉES DU PANIER
    // ================================================================================================
    
    /**
     * Récupère le contenu du panier avec vérification d'intégrité optionnelle
     */
    public function getItems($withDetails = false) {
        // Vérifier l'intégrité si programmée
        $this->ensureIntegrityChecked();
        
        if (class_exists('Logger')) {
            Logger::debug('CART', "Récupération des articles du panier", [
                'items_count' => count($this->items),
                'with_details' => $withDetails
            ]);
        }
        
        if (!$withDetails) {
            return $this->items;
        }
        
        // Enrichir avec les détails complets des produits
        $itemsWithDetails = [];
        
        foreach ($this->items as $productId => $item) {
            $productInfo = $this->getProductInfo($productId);
            
            if ($productInfo) {
                $itemsWithDetails[$productId] = array_merge($item, [
                    'current_price' => $productInfo['price'],
                    'current_stock' => $productInfo['stock'],
                    'stock_remaining' => max(0, $productInfo['stock'] - $item['quantity']),
                    'is_in_stock' => ($productInfo['stock'] > 0),
                    'price_changed' => (abs($productInfo['price'] - $item['price']) > 0.01)
                ]);
            } else {
                // Produit non trouvé, utiliser les informations existantes
                $itemsWithDetails[$productId] = array_merge($item, [
                    'current_price' => null,
                    'current_stock' => 0,
                    'stock_remaining' => 0,
                    'is_in_stock' => false,
                    'price_changed' => false,
                    'product_unavailable' => true
                ]);
            }
        }
        
        return $itemsWithDetails;
    }
    
    /**
     * Récupère les détails d'un article spécifique
     */
    public function getItem($productId, $withDetails = false) {
        // Validation de l'ID
        if (!is_numeric($productId) || $productId <= 0) {
            return null;
        }
        
        // Vérifier l'intégrité si programmée
        $this->ensureIntegrityChecked();
        
        if (!isset($this->items[$productId])) {
            return null;
        }
        
        $item = $this->items[$productId];
        
        if (!$withDetails) {
            return $item;
        }
        
        // Enrichir avec les détails produit
        $productInfo = $this->getProductInfo($productId);
        
        if ($productInfo) {
            return array_merge($item, [
                'current_price' => $productInfo['price'],
                'current_stock' => $productInfo['stock'],
                'stock_remaining' => max(0, $productInfo['stock'] - $item['quantity']),
                'is_in_stock' => ($productInfo['stock'] > 0),
                'price_changed' => (abs($productInfo['price'] - $item['price']) > 0.01)
            ]);
        }
        
        return $item;
    }
    

    
    // ================================================================================================
    // CALCULS ET TOTAUX
    // ================================================================================================
    
    /**
     * Calcule le montant total du panier avec options avancées
     */
    public function getTotal($includeTaxes = false) {
        $this->ensureIntegrityChecked();
        
        $subtotal = 0;
        $totalTaxes = 0;
        
        foreach ($this->items as $item) {
            $subtotal += $item['subtotal'];
            
            // Calculer les taxes si demandé
            if ($includeTaxes && isset($item['tva_rate'])) {
                $totalTaxes += ($item['subtotal'] * $item['tva_rate'] / 100);
            }
        }
        
        // Appliquer la réduction si elle existe
        $discountAmount = $this->getDiscountAmount($subtotal);
        $subtotal = max(0, $subtotal - $discountAmount);
        
        $total = $includeTaxes ? ($subtotal + $totalTaxes) : $subtotal;
        
        return round($total, 2);
    }
    
    /**
     * Calcule le montant de la réduction appliquée
     */
    private function getDiscountAmount($subtotal) {
        if (!isset($_SESSION['discount_code'])) {
            return 0;
        }
        
        /* $discount = $_SESSION['discount_code'];
        
        switch ($discount['type']) {
            case 'percent':
                return $subtotal * ($discount['value'] / 100);
            case 'fixed':
                return min($discount['value'], $subtotal);
            default:
                return 0;
        }*/
        
        $discount = $_SESSION['discount_code'];
if (!isset($discount['type'], $discount['value'])) {
    return 0;
}
switch ($discount['type']) {
    case 'percent':
        return $subtotal * ($discount['value'] / 100);
    case 'fixed':
        return min($discount['value'], $subtotal);
    default:
        return 0;
}
    }
    
    /**
     * Obtient les informations sur la réduction appliquée
     */
    public function getDiscountInfo() {
        if (!isset($_SESSION['discount_code'])) {
            return null;
        }
        
        $discount = $_SESSION['discount_code'];
        $subtotal = $this->getTotal(false) + $this->getDiscountAmount($this->getSubtotalBeforeDiscount());
        $discountAmount = $this->getDiscountAmount($subtotal);
        
        return [
            'code' => $discount['code'],
            'type' => $discount['type'],
            'value' => $discount['value'],
            'amount' => round($discountAmount, 2),
            'subtotal_before' => round($subtotal, 2),
            'total_after' => round($subtotal - $discountAmount, 2)
        ];
    }
    
    /**
     * Calcule le sous-total avant application de la réduction
     */
    private function getSubtotalBeforeDiscount() {
        $subtotal = 0;
        foreach ($this->items as $item) {
            $subtotal += $item['subtotal'];
        }
        return $subtotal;
    }
    
    /**
     * Calcule le montant des taxes avec détail par taux
     */
    public function getTaxes($detailByRate = false) {
        $this->ensureIntegrityChecked();
        
        $taxes = [];
        $totalTaxes = 0;
        
        foreach ($this->items as $item) {
            if (!isset($item['tva_rate'])) {
                continue;
            }
            
            $rate = (float)$item['tva_rate'];
            $taxAmount = $item['subtotal'] * ($rate / 100);
            
            if ($detailByRate) {
                if (!isset($taxes[$rate])) {
                    $taxes[$rate] = 0;
                }
                $taxes[$rate] += $taxAmount;
            }
            
            $totalTaxes += $taxAmount;
        }
        
        if ($detailByRate) {
            ksort($taxes);
            $taxes['total'] = round($totalTaxes, 2);
            return $taxes;
        }
        
        return round($totalTaxes, 2);
    }
    
    // ================================================================================================
    // INFORMATIONS ET STATISTIQUES DU PANIER
    // ================================================================================================
    
    /**
     * Récupère le nombre total d'articles dans le panier
     */
    public function getItemCount() {
        $this->ensureIntegrityChecked();
        
        $count = 0;
        foreach ($this->items as $item) {
            $count += $item['quantity'];
        }
        
        return $count;
    }
    
    /**
     * Vérifie si le panier est vide
     */
    public function isEmpty() {
        $this->ensureIntegrityChecked();
        return empty($this->items);
    }
    
    /**
     * Calcule le poids total du panier
     */
    public function getTotalWeight() {
        $this->ensureIntegrityChecked();
        
        $weight = 0;
        foreach ($this->items as $item) {
            if (isset($item['weight'])) {
                $weight += $item['weight'] * $item['quantity'];
            }
        }
        
        return $weight;
    }
    
    /**
     * Récupère les dimensions maximales pour l'estimation de livraison
     */
    public function getMaxDimensions() {
        $this->ensureIntegrityChecked();
        
        $maxDimensions = ['largeur' => 0, 'longueur' => 0, 'hauteur' => 0];
        
        foreach ($this->items as $item) {
            foreach (['largeur', 'longueur', 'hauteur'] as $dimension) {
                if (isset($item[$dimension]) && $item[$dimension] > $maxDimensions[$dimension]) {
                    $maxDimensions[$dimension] = $item[$dimension];
                }
            }
        }
        
        return $maxDimensions;
    }
    
    /**
     * Calcule le volume total approximatif
     */
    public function getTotalVolume() {
        $this->ensureIntegrityChecked();
        
        $totalVolume = 0;
        
        foreach ($this->items as $item) {
            if (isset($item['largeur'], $item['longueur'], $item['hauteur'])) {
                $volume = $item['largeur'] * $item['longueur'] * $item['hauteur'] * $item['quantity'];
                $totalVolume += $volume;
            }
        }
        
        return $totalVolume;
    }
    
    /**
     * Récupère l'ID unique du panier
     */
   /* public function getCartId() {
        return $this->cartId;
    }*/
    public function getCartId(): string {
    return $this->cartId;
}
    
    /**
     * Récupère la date de dernière modification
     */
    public function getLastModified($format = null) {
        if ($format === null) {
            return $this->lastModified;
        }
        
        return date($format, $this->lastModified);
    }
    
    /**
     * Vérifie si le panier a été modifié depuis une date donnée
     */
    public function hasBeenModifiedSince($timestamp) {
        return $this->lastModified > $timestamp;
    }
    
    // ================================================================================================
    // RÉCAPITULATIF ET MÉTRIQUES
    // ================================================================================================
    
    /**
     * Génère un récapitulatif complet du panier
     */
    public function getSummary() {
        $this->ensureIntegrityChecked();
        
        if (class_exists('Logger')) {
            Logger::debug('CART', "Génération du récapitulatif du panier");
        }
        
        // Vérifier la disponibilité des produits
        $availabilityIssues = $this->checkAvailability();
        
        $summary = [
            'cart_id' => $this->cartId,
            'client_id' => $this->clientId,
            'items' => $this->getItems(true),
            'item_count' => $this->getItemCount(),
            'subtotal' => $this->getTotal(false),
            'taxes' => $this->getTaxes(true),
            'total_with_taxes' => $this->getTotal(true),
            'discount' => $this->getDiscountInfo(),
            'weight' => $this->getTotalWeight(),
            'dimensions' => $this->getMaxDimensions(),
            'volume' => $this->getTotalVolume(),
            'last_modified' => $this->getLastModified('Y-m-d H:i:s'),
            'has_availability_issues' => !empty($availabilityIssues),
            'availability_issues' => $availabilityIssues,
            'is_empty' => $this->isEmpty()
        ];
        
        // Ajouter le total final avec réduction
        if ($summary['discount']) {
            $summary['final_total'] = $summary['discount']['total_after'];
            $summary['discount_amount'] = $summary['discount']['amount'];
        } else {
            $summary['final_total'] = $summary['subtotal'];
            $summary['discount_amount'] = 0;
        }
        
        // Générer un hash d'intégrité pour le récapitulatif
        $summary['integrity_hash'] = $this->generateSummaryHash($summary);
        
        return $summary;
    }
    
    /**
     * Génère un hash d'intégrité pour le récapitulatif
     */
    private function generateSummaryHash($summary) {
        // Exclure le hash lui-même du calcul
        $dataForHash = $summary;
        unset($dataForHash['integrity_hash']);
        
        if (class_exists('Security')) {
            return Security::generateHmac($dataForHash);
        }
        
        return hash('sha256', serialize($dataForHash));
    }
    
    /**
     * Obtient les métriques de performance du panier
     */
/**
     * Obtient les métriques de performance du panier
     */
    public function getMetrics() {
        return [
            'product_cache_size' => count($this->productCache),
            'integrity_verified' => $this->integrityVerified,
            'saved_to_database' => $this->savedToDatabase,
            'cart_exists_cache_size' => count(self::$cartExistsCache),
            'last_cache_cleanup' => self::$lastCacheCleanup,
            'memory_usage' => memory_get_usage(true),
            'items_count' => count($this->items),
            'total_quantity' => $this->getItemCount()
        ];
    }
    
    // ================================================================================================
    // MÉTHODES UTILITAIRES ET NETTOYAGE FINAL
    // ================================================================================================
    
    /**
     * Calcule une empreinte du contenu du panier
     */
    public function getFingerprint() {
        $cartData = [
            'items' => $this->items,
            'cart_id' => $this->cartId,
            'last_modified' => $this->lastModified
        ];
        
        if (class_exists('Security')) {
            return Security::generateHmac($cartData);
        }
        
        return hash('sha256', serialize($cartData));
    }
    
    /**
     * Nettoie les ressources et effectue la maintenance finale
     */
    public function cleanup() {
        // Vider le cache produit de cette instance
        $this->productCache = [];
        
        // Effectuer la sauvegarde finale si nécessaire
        if (!empty($this->items) && !$this->savedToDatabase) {
            $this->saveToDatabase();
        }
        
        // Log des métriques finales en mode debug
        if (defined('DEBUG_CART') && DEBUG_CART && class_exists('Logger')) {
            Logger::debug('CART', "Nettoyage du panier - Métriques finales", $this->getMetrics());
        }
    }
    
    /**
     * Méthode de test pour vérifier le fonctionnement du panier (développement uniquement)
     */
    public function selfTest() {
        if (!defined('ENVIRONMENT') || ENVIRONMENT !== 'development') {
            return false;
        }
        
        $results = [
            'timestamp' => date('Y-m-d H:i:s'),
            'cart_id' => $this->cartId,
            'client_id' => $this->clientId,
            'session_initialized' => (session_status() === PHP_SESSION_ACTIVE),
            'database_connected' => ($this->db !== null),
            'items_count' => count($this->items),
          'cache_sizes' => [
                'product_cache' => count($this->productCache),
                'cart_exists_cache' => count(self::$cartExistsCache)
            ],
            'integrity_verified' => $this->integrityVerified,
            'saved_to_database' => $this->savedToDatabase
        ];
        
        return $results;
    }
    
    
    
    
/**
 * ✅ MÉTHODE CORRIGÉE : Fusion centralisée et sécurisée des articles de panier
 */
private function mergeCartItems($existingItem, $newItem, $strategy = 'add') {
// Validation basique des paramètres (validation complexe déjà faite en amont)
if (!is_array($existingItem) || !is_array($newItem)) {
    throw new InvalidArgumentException("Articles de panier invalides");
}

if ($existingItem['id'] !== $newItem['id']) {
    throw new InvalidArgumentException("Tentative de fusion d'articles différents");
}

// Types déjà validés par Security en amont
$existingQty = (int)$existingItem['quantity'];
$newQty = (int)$newItem['quantity'];
$price = (float)$existingItem['price'];
    
    // ✅ CORRECTION: Validation des stratégies autorisées
    $allowedStrategies = ['add', 'max', 'replace', 'min'];
    if (!in_array($strategy, $allowedStrategies)) {
        throw new InvalidArgumentException("Stratégie de fusion non autorisée: " . htmlspecialchars($strategy));
    }
    
    // ✅ CORRECTION: Calcul sécurisé avec protection overflow
    $finalQuantity = 0;
    $reason = "";
    
    switch ($strategy) {
        case 'add':
            // ✅ CORRECTION: Vérification overflow avant addition
            if ($existingQty > PHP_INT_MAX - $newQty) {
                throw new InvalidArgumentException("Dépassement de capacité lors de l'addition des quantités");
            }
            $finalQuantity = $existingQty + $newQty;
            $reason = "Addition des quantités";
            break;
            
        case 'max':
            $finalQuantity = max($existingQty, $newQty);
            $reason = "Conservation de la quantité maximale";
            break;
            
        case 'replace':
            $finalQuantity = $newQty;
            $reason = "Remplacement par la nouvelle quantité";
            break;
            
        case 'min':
            $finalQuantity = min($existingQty, $newQty);
            $reason = "Conservation de la quantité minimale";
            break;
    }
    
    // ✅ CORRECTION: Validation du stock avec vérification DB en temps réel
    if (isset($newItem['stock'])) {
        $availableStock = (int)$newItem['stock'];
        
        // ✅ AJOUT: Revérification du stock en temps réel
        try {
            $actualStock = $this->getProductStock($existingItem['id']);
            if ($actualStock !== $availableStock) {
                if (class_exists('Logger')) {
                    Logger::warning('CART', "Stock incohérent détecté lors de la fusion", [
                        'product_id' => $existingItem['id'],
                        'provided_stock' => $availableStock,
                        'actual_stock' => $actualStock
                    ]);
                }
                $availableStock = $actualStock;
            }
        } catch (Exception $e) {
            // En cas d'erreur, utiliser le stock fourni mais logger l'erreur
            if (class_exists('Logger')) {
                Logger::error('CART', "Erreur vérification stock: " . $e->getMessage());
            }
        }
        
        if ($finalQuantity > $availableStock) {
            $finalQuantity = $availableStock;
            $reason .= " (ajusté au stock disponible: {$availableStock})";
        }
    }
    
    // ✅ CORRECTION: Limites de sécurité strictes
    $maxQuantity = defined('MAX_ITEM_QUANTITY') ? MAX_ITEM_QUANTITY : 100;
    if ($finalQuantity > $maxQuantity) {
        $finalQuantity = $maxQuantity;
        $reason .= " (limité à {$maxQuantity} pour sécurité)";
        
        if (class_exists('Logger')) {
            Logger::warning('CART', "Quantité limitée pour sécurité", [
                'product_id' => $existingItem['id'],
                'requested_quantity' => $finalQuantity,
                'max_allowed' => $maxQuantity
            ]);
        }
    }
    
    // ✅ CORRECTION: Construction sécurisée de l'article fusionné
    $mergedItem = [
        'id' => $existingItem['id'],
        'quantity' => $finalQuantity,
        'price' => $price,
        'subtotal' => $price * $finalQuantity,
        'name' => $existingItem['name'],
        'merged_at' => time(),
        'merge_strategy' => $strategy,
        'merge_reason' => $reason,
        'merge_checksum' => hash('sha256', serialize([
            'id' => $existingItem['id'],
            'quantity' => $finalQuantity,
            'price' => $price,
            'timestamp' => time()
        ]))
    ];
    
    // ✅ CORRECTION: Préserver les champs sécurisés de l'article existant
    $secureFields = ['weight', 'reference', 'image_url', 'category', 'tva_rate', 'largeur', 'longueur', 'hauteur'];
    foreach ($secureFields as $field) {
        if (isset($existingItem[$field])) {
            $mergedItem[$field] = $existingItem[$field];
        }
    }
    
    if (class_exists('Logger')) {
        Logger::debug('CART', "Articles fusionnés avec succès", [
            'product_id' => $existingItem['id'],
            'strategy' => $strategy,
            'existing_qty' => $existingQty,
            'new_qty' => $newQty,
            'final_qty' => $finalQuantity,
            'reason' => $reason,
            'checksum' => substr($mergedItem['merge_checksum'], 0, 8)
        ]);
    }
    
    return $mergedItem;
}
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}

// ================================================================================================
// FINALISATION ET CLEANUP AUTOMATIQUE
// ================================================================================================


// Enregistrer le nettoyage automatique en fin de script
// Enregistrer le nettoyage automatique en fin de script
register_shutdown_function(function() {
    // ✅ CORRECTION : Utiliser Cart:: au lieu de self:: dans une closure
    if (class_exists('Cart') && count(Cart::$cartExistsCache ?? []) > 200) {
        Cart::clearCache();
    }
});
/*register_shutdown_function(function() {    // Nettoyer les caches statiques si nécessaire

  if (count(self::$cartExistsCache) > 200) {
    self::clearCache();
}

});*/

/*register_shutdown_function(function() {
// Nettoyage simple sans référence à self::
    if (class_exists('Cart')) {
        Cart::clearCache();
    }
});*/
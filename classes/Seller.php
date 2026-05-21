<?php
/**
 * Seller Class - Handles seller management
 */

class Seller {
    private $pdo;
    
    public function __construct($pdo) {
        $this->pdo = $pdo;
    }

    /**
     * Register seller
     */
    public function registerSeller($email, $username, $password, $confirm_password, $language = 'uz') {
        $response = array('success' => false, 'message' => '');

        // Validation
        if (empty($email) || empty($username) || empty($password) || empty($confirm_password)) {
            $response['message'] = 'Barcha maydonlarni to\'ldiring';
            return $response;
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $response['message'] = 'Email manzili noto\'g\'ri';
            return $response;
        }

        if (strlen($password) < 6) {
            $response['message'] = 'Parol kamida 6 belgidan iborat bo\'lishi kerak';
            return $response;
        }

        if ($password !== $confirm_password) {
            $response['message'] = 'Parollar mos kelmaydi';
            return $response;
        }

        // Check if username exists
        $stmt = $this->pdo->prepare("SELECT id FROM sellers WHERE username = ?");
        $stmt->execute([$username]);
        if ($stmt->fetch()) {
            $response['message'] = 'Bu username allaqachon mavjud';
            return $response;
        }

        // Check if email exists
        $stmt = $this->pdo->prepare("SELECT id FROM sellers WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            $response['message'] = 'Bu email allaqachon mavjud';
            return $response;
        }

        // Generate verification code
        $verification_code = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $password_hash = password_hash($password, PASSWORD_BCRYPT);

        try {
            // Insert seller
            $stmt = $this->pdo->prepare("
                INSERT INTO sellers (email, username, password, verification_code, ip_address, language)
                VALUES (?, ?, ?, ?, ?, ?)
            ");
            $stmt->execute([
                $email,
                $username,
                $password_hash,
                $verification_code,
                $this->getClientIP(),
                $language
            ]);

            $seller_id = $this->pdo->lastInsertId();

            // Send verification email
            $this->sendVerificationEmail($email, $verification_code);

            $response['success'] = true;
            $response['message'] = 'Ro\'yxatdan o\'tish muvaffaqiyatli. Email manzilingizni tekshiring';
            $response['seller_id'] = $seller_id;

        } catch (Exception $e) {
            $response['message'] = 'Xatolik: ' . $e->getMessage();
        }

        return $response;
    }

    /**
     * Login seller
     */
    public function loginSeller($username, $password) {
        $response = array('success' => false, 'message' => '');

        if (empty($username) || empty($password)) {
            $response['message'] = 'Username va parolni kiritish majburiy';
            return $response;
        }

        // Check if seller exists
        $stmt = $this->pdo->prepare("SELECT * FROM sellers WHERE username = ?");
        $stmt->execute([$username]);
        $seller = $stmt->fetch();

        if (!$seller) {
            $response['message'] = 'Username yoki parol noto\'g\'ri';
            return $response;
        }

        // Check account status
        if ($seller['account_status'] === 'deleted') {
            $response['message'] = 'O\'chirilgan sotuvchi';
            return $response;
        }

        // Verify password
        if (!password_verify($password, $seller['password'])) {
            $response['message'] = 'Username yoki parol noto\'g\'ri';
            return $response;
        }

        // Check email verification
        if (!$seller['email_verified']) {
            $response['message'] = 'Email tasdiqlangan emas';
            return $response;
        }

        // Create session
        $session_data = array(
            'seller_id' => $seller['id'],
            'username' => $seller['username'],
            'email' => $seller['email'],
            'type' => 'seller',
            'is_verified' => $seller['is_verified']
        );

        $_SESSION['seller'] = $session_data;

        // Update login info
        $stmt = $this->pdo->prepare("
            UPDATE sellers SET last_login = NOW(), ip_address = ? WHERE id = ?
        ");
        $stmt->execute([$this->getClientIP(), $seller['id']]);

        $response['success'] = true;
        $response['message'] = 'Muvaffaqiyatli kirdiniz';
        $response['seller_id'] = $seller['id'];

        return $response;
    }

    /**
     * Get seller profile
     */
    public function getProfile($seller_id) {
        $stmt = $this->pdo->prepare("SELECT * FROM sellers WHERE id = ?");
        $stmt->execute([$seller_id]);
        return $stmt->fetch();
    }

    /**
     * Get seller statistics
     */
    public function getStatistics($seller_id) {
        $stats = array();

        // Total products
        $stmt = $this->pdo->prepare("SELECT COUNT(*) as count FROM products WHERE seller_id = ?");
        $stmt->execute([$seller_id]);
        $stats['total_products'] = $stmt->fetch()['count'];

        // Total orders
        $stmt = $this->pdo->prepare("SELECT COUNT(*) as count FROM orders WHERE seller_id = ?");
        $stmt->execute([$seller_id]);
        $stats['total_orders'] = $stmt->fetch()['count'];

        // Total sales
        $stmt = $this->pdo->prepare("SELECT SUM(total_price) as total FROM orders WHERE seller_id = ?");
        $stmt->execute([$seller_id]);
        $result = $stmt->fetch();
        $stats['total_sales'] = $result['total'] ? $result['total'] : 0;

        // Products in carts
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) as count FROM cart c
            JOIN products p ON c.product_id = p.id
            WHERE p.seller_id = ?
        ");
        $stmt->execute([$seller_id]);
        $stats['in_carts'] = $stmt->fetch()['count'];

        // Balance
        $stmt = $this->pdo->prepare("SELECT balance FROM sellers WHERE id = ?");
        $stmt->execute([$seller_id]);
        $result = $stmt->fetch();
        $stats['balance'] = $result['balance'] ? $result['balance'] : 0;

        return $stats;
    }

    /**
     * Request verification
     */
    public function requestVerification($seller_id) {
        $response = array('success' => false, 'message' => '');

        // Get seller
        $stmt = $this->pdo->prepare("SELECT * FROM sellers WHERE id = ?");
        $stmt->execute([$seller_id]);
        $seller = $stmt->fetch();

        if (!$seller) {
            $response['message'] = 'Sotuvchi topilmadi';
            return $response;
        }

        if ($seller['is_verified']) {
            $response['message'] = 'Siz allaqachon tasdiqlanibsiz';
            return $response;
        }

        // Create notification for admin
        $stmt = $this->pdo->prepare("
            INSERT INTO notifications (admin_id, type, title, message)
            VALUES (NULL, 'verification_request', 'Tasdiqlash So\'rovi', 
                'Sotuvchi ' . $seller['username'] . ' tasdiqlash so\'rov qildi')
        ");
        $stmt->execute();

        $response['success'] = true;
        $response['message'] = 'Tasdiqlash so\'rovi yuborildi. Admin ko\'rib chiqadi';

        return $response;
    }

    /**
     * Request withdrawal
     */
    public function requestWithdrawal($seller_id, $amount, $wallet_address) {
        $response = array('success' => false, 'message' => '');

        if (empty($wallet_address) || $amount <= 0) {
            $response['message'] = 'Hamyon manzili va summa to\'g\'ri kiritilishi kerak';
            return $response;
        }

        // Get seller
        $stmt = $this->pdo->prepare("SELECT balance FROM sellers WHERE id = ?");
        $stmt->execute([$seller_id]);
        $seller = $stmt->fetch();

        if (!$seller) {
            $response['message'] = 'Sotuvchi topilmadi';
            return $response;
        }

        if ($seller['balance'] < $amount) {
            $response['message'] = 'Balansingizda yetarli mablag\' yo\'q';
            return $response;
        }

        // Check if there's a pending withdrawal
        $stmt = $this->pdo->prepare("
            SELECT id FROM withdrawal_requests 
            WHERE seller_id = ? AND status = 'pending'
        ");
        $stmt->execute([$seller_id]);
        if ($stmt->fetch()) {
            $response['message'] = 'Siz allaqachon bir mablag\' yechish so\'rovini yuboribsiz';
            return $response;
        }

        try {
            // Create withdrawal request
            $stmt = $this->pdo->prepare("
                INSERT INTO withdrawal_requests (seller_id, amount, wallet_address, status)
                VALUES (?, ?, ?, 'pending')
            ");
            $stmt->execute([$seller_id, $amount, $wallet_address]);

            $response['success'] = true;
            $response['message'] = 'Mablag\' yechish so\'rovi yuborildi. 1 daqiqadan 4 soatgacha vaqt ketishi mumkin';

        } catch (Exception $e) {
            $response['message'] = 'Xatolik: ' . $e->getMessage();
        }

        return $response;
    }

    /**
     * Get withdrawal requests
     */
    public function getWithdrawalRequests($seller_id) {
        $stmt = $this->pdo->prepare("
            SELECT * FROM withdrawal_requests 
            WHERE seller_id = ?
            ORDER BY requested_at DESC
        ");
        $stmt->execute([$seller_id]);
        return $stmt->fetchAll();
    }

    /**
     * Delete account
     */
    public function deleteAccount($seller_id) {
        try {
            // Get seller data
            $stmt = $this->pdo->prepare("SELECT * FROM sellers WHERE id = ?");
            $stmt->execute([$seller_id]);
            $seller = $stmt->fetch();

            if (!$seller) {
                return array('success' => false, 'message' => 'Sotuvchi topilmadi');
            }

            // Delete all seller's products
            $stmt = $this->pdo->prepare("DELETE FROM products WHERE seller_id = ?");
            $stmt->execute([$seller_id]);

            // Delete seller
            $stmt = $this->pdo->prepare("DELETE FROM sellers WHERE id = ?");
            $stmt->execute([$seller_id]);

            return array('success' => true, 'message' => 'Hisob o\'chirildi');

        } catch (Exception $e) {
            return array('success' => false, 'message' => 'Xatolik: ' . $e->getMessage());
        }
    }

    /**
     * Get client IP
     */
    private function getClientIP() {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
        } else {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        return trim($ip);
    }

    /**
     * Send verification email
     */
    private function sendVerificationEmail($email, $code) {
        $subject = 'KeySave Sotuvchi - Email Tasdiqlash Kodi';
        $message = "Sizning tasdiqlash kodingiz: " . $code . "\n\n";
        $message .= "Ushbu kod 15 minut davomida amal qiladi.";
        
        $headers = "From: " . FROM_EMAIL . "\r\n";
        $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
        
        mail($email, $subject, $message, $headers);
    }
}
?>

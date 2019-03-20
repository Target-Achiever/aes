<?php

echo custom_decrypt('QnhpQktDaUJnUmhzUDcxOXdGUTg0Zz09');

/* ============        Encryption       ============== */
function custom_encrypt($string) {

    $secure_key = "0008754063617000";
    $output = false;
    $encrypt_method = "AES-256-CBC";
    $secret_key =  $secure_key;
    $secret_iv = strrev($secure_key);
    // hash
    $key = hash('sha256', $secret_key);
    
    // iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
    $iv = substr(hash('sha256', $secret_iv), 0, 16);
    $output_str = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
    $output = rtrim(strtr(base64_encode($output_str), '+/', '-_'), '='); 
    return $output;
}

/* ================== Decryption ================= */
function custom_decrypt($string) {

    $secure_key = "0008754063617000";
    $output = false;
    $encrypt_method = "AES-256-CBC";
    $secret_key =  $secure_key;
    $secret_iv = strrev($secure_key);

    // hash
    $key = hash('sha256', $secret_key);
    // iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
    $iv = substr(hash('sha256', $secret_iv), 0, 16);
    $decode_str = base64_decode(str_pad(strtr($string, '-_', '+/'), strlen($string) % 4, '=', STR_PAD_RIGHT)); 
    $output = openssl_decrypt($decode_str, $encrypt_method, $key, 0, $iv);

    return $output;
}


?>
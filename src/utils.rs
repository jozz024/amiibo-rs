pub struct TypeOr {
    pub hmac_key: Vec<u8>,
    pub aes_key: Option<Vec<u8>>,
    pub aes_iv: Option<Vec<u8>>
}
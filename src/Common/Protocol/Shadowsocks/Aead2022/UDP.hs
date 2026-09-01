module Common.Protocol.Shadowsocks.Aead2022.UDP (getNonceLength, newCipher) where

import Common.Crypto (Key)
import Common.Crypto.Aead (CipherKind (..), CipherMethod, newCipherMethod)
import Common.Protocol.Shadowsocks (Salt (Salt))
import Common.Protocol.Shadowsocks.Aead2022 (sessionSubKey)
import qualified Data.ByteString as B
import Data.ByteString.Builder (toLazyByteString, word64BE)
import Data.Word (Word64)

getNonceLength :: CipherKind -> Int
getNonceLength Aead2022Blake3Aes128Gcm = 0
getNonceLength Aead2022Blake3Aes256Gcm = 0
getNonceLength Aead2022Blake3ChaCha8Poly1305 = 24
getNonceLength Aead2022Blake3ChaCha20Poly1305 = 24
getNonceLength kind = error $ show kind ++ " is not an AEAD 2022 cipher"

newCipher :: CipherKind -> Key -> Word64 -> CipherMethod
newCipher Aead2022Blake3Aes128Gcm key sessionId = do
  let sessionId' = B.toStrict $ toLazyByteString $ word64BE sessionId
      key' = sessionSubKey key (Salt sessionId')
  newCipherMethod Aead2022Blake3Aes128Gcm key'
newCipher Aead2022Blake3Aes256Gcm key sessionId = do
  let sessionId' = B.toStrict $ toLazyByteString $ word64BE sessionId
      key' = sessionSubKey key (Salt sessionId')
  newCipherMethod Aead2022Blake3Aes256Gcm key'
newCipher Aead2022Blake3ChaCha8Poly1305 key _ = newCipherMethod XChaCha8Poly1305 key
newCipher Aead2022Blake3ChaCha20Poly1305 key _ = newCipherMethod XChaCha20Poly1305 key
newCipher other _ _ = error $ show other ++ " is not an AEAD 2022 cipher"

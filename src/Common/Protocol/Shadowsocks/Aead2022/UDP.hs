module Common.Protocol.Shadowsocks.Aead2022.UDP (getNonceLength, newCipher) where

import Common.Crypto (Key)
import Common.Crypto.Aead (CipherKind (..), CipherMethod, newCipherMethod)
import Common.Exception (AppExceptionKind (InvariantError), throwApp)
import Common.Protocol.Shadowsocks (Salt (Salt))
import Common.Protocol.Shadowsocks.Aead2022 (sessionCipherKey)
import Control.Monad.Catch (MonadThrow)
import qualified Data.ByteString as B
import Data.ByteString.Builder (toLazyByteString, word64BE)
import Data.Word (Word64)
import GHC.Stack (HasCallStack)

getNonceLength :: (MonadThrow m, HasCallStack) => CipherKind -> m Int
getNonceLength Aead2022Blake3Aes128Gcm = pure 0
getNonceLength Aead2022Blake3Aes256Gcm = pure 0
getNonceLength Aead2022Blake3ChaCha8Poly1305 = pure 24
getNonceLength Aead2022Blake3ChaCha20Poly1305 = pure 24
getNonceLength kind = throwApp InvariantError $ show kind ++ " is not an AEAD 2022 cipher"

newCipher :: (MonadThrow m, HasCallStack) => CipherKind -> Key -> Word64 -> m CipherMethod
newCipher kind@Aead2022Blake3Aes128Gcm key sessionId = do
  let sessionId' = B.toStrict $ toLazyByteString $ word64BE sessionId
      key' = sessionCipherKey kind key (Salt sessionId')
  newCipherMethod Aead2022Blake3Aes128Gcm key'
newCipher kind@Aead2022Blake3Aes256Gcm key sessionId = do
  let sessionId' = B.toStrict $ toLazyByteString $ word64BE sessionId
      key' = sessionCipherKey kind key (Salt sessionId')
  newCipherMethod Aead2022Blake3Aes256Gcm key'
newCipher Aead2022Blake3ChaCha8Poly1305 key _ = newCipherMethod XChaCha8Poly1305 key
newCipher Aead2022Blake3ChaCha20Poly1305 key _ = newCipherMethod XChaCha20Poly1305 key
newCipher other _ _ = throwApp InvariantError $ show other ++ " is not an AEAD 2022 cipher"

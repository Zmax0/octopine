{-# LANGUAGE OverloadedStrings #-}

module Common.Protocol.Shadowsocks.Aead2022 (isAead2022, supportEih, passwordToKeys, sessionSubKey, identitySubKey) where

import qualified BLAKE3
import Common.Crypto (Key)
import Common.Crypto.Aead (CipherKind (..))
import Common.Exception (AppExceptionKind (ConfigError), throwApp)
import Common.Protocol.Shadowsocks (Salt (Salt))
import Control.Monad.Catch (MonadThrow)
import qualified Data.ByteArray.Sized as Sized
import Data.ByteString (StrictByteString)
import qualified Data.ByteString.Base64 as B64
import Data.Text (splitOn)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import GHC.Stack (HasCallStack)

isAead2022 :: CipherKind -> Bool
isAead2022 Aead2022Blake3Aes128Gcm = True
isAead2022 Aead2022Blake3Aes256Gcm = True
isAead2022 Aead2022Blake3ChaCha8Poly1305 = True
isAead2022 Aead2022Blake3ChaCha20Poly1305 = True
isAead2022 _ = False

supportEih :: CipherKind -> Bool
supportEih Aead2022Blake3Aes128Gcm = True
supportEih Aead2022Blake3Aes256Gcm = True
supportEih _ = False

passwordToKeys :: (MonadThrow t, HasCallStack) => T.Text -> t (Key, [Key])
passwordToKeys password = do
  let parts = splitOn ":" password
  keys <- mapM (\part -> either (throwApp ConfigError . ("invalid shadowsocks identity key: " ++)) return (B64.decode $ TE.encodeUtf8 part)) parts
  case reverse keys of
    [] -> throwApp ConfigError "empty shadowsocks password"
    key : identityKeys -> return (key, reverse identityKeys)

sessionSubKey :: Key -> Salt -> Key
sessionSubKey key (Salt salt) = do
  let context = "shadowsocks 2022 session subkey" :: StrictByteString
      digest = BLAKE3.derive context [key <> salt] :: BLAKE3.Digest BLAKE3.DEFAULT_DIGEST_LEN
  Sized.unSizedByteArray (Sized.convert digest :: Sized.SizedByteArray BLAKE3.DEFAULT_DIGEST_LEN StrictByteString)

identitySubKey :: Key -> Salt -> Key
identitySubKey key (Salt salt) = do
  let context = "shadowsocks 2022 identity subkey" :: StrictByteString
      digest = BLAKE3.derive context [key <> salt] :: BLAKE3.Digest BLAKE3.DEFAULT_DIGEST_LEN
  Sized.unSizedByteArray (Sized.convert digest :: Sized.SizedByteArray BLAKE3.DEFAULT_DIGEST_LEN StrictByteString)
